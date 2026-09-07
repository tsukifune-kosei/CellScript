use super::artifact::{ArtifactArgs, ArtifactOperation};
use crate::docgen::{DocGenerator, OutputFormat};
use crate::error::{CompileError, Result};
use crate::fmt::format_default;
use crate::package::{Dependency, DetailedDependency, Lockfile, PackageManager, PackageManifest, PolicyConfig};
use crate::runtime_errors::{runtime_error_info, runtime_error_info_by_code, CellScriptRuntimeErrorInfo, ALL_RUNTIME_ERRORS};
use crate::{
    compile_path, compile_path_metadata_with_diagnostics, compile_path_with_entry_action, compile_path_with_entry_lock,
    compile_path_with_executable_surface_policy, default_metadata_path_for_artifact, default_output_path_for_input,
    load_modules_for_input, resolve_input_path, validate_artifact_metadata, validate_source_units_on_disk, ArtifactFormat,
    CompileEntryScope, CompileMetadata, CompileOptions, EntryWitnessArg, ExecutableSurfacePolicy, ParamMetadata, ProofPlanMetadata,
    TargetProfile, ENTRY_WITNESS_ABI, ENTRY_WITNESS_PLACEMENT_ABI, ENTRY_WITNESS_PLACEMENT_FIELD, ENTRY_WITNESS_PLACEMENT_SOURCE,
};
use base64::Engine;
use camino::Utf8Path;
#[cfg(feature = "vm-runner")]
use ckb_vm::{
    cost_model::estimate_cycles, machine::VERSION2, Bytes, DefaultCoreMachine, DefaultMachineBuilder, DefaultMachineRunner,
    SparseMemory, SupportMachine, TraceMachine, WXorXMemory, ISA_B, ISA_IMC, ISA_MOP,
};
use colored::Colorize;
use ring::signature::KeyPair;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{IsTerminal, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

const CKB_STANDARD_COMPAT_MANIFEST_SCHEMA: &str = "cellscript-ckb-standard-compat-v0.16";
const CKB_STANDARD_FIXTURE_SCHEMA: &str = "cellscript-ckb-fixture-v0.16";
const ICKB_CLAIM_MANIFEST_SCHEMA: &str = "cellscript-ickb-claim-manifest-v1";
const ICKB_DIFF_MATRIX_SCHEMA: &str = "cellscript-ickb-diff-matrix-v1";
const ICKB_DIFF_EVIDENCE_LEVEL: &str = "DIFFERENTIAL_CKB_VM_EXECUTED";
const ICKB_REQUIRED_PRODUCTION_EVIDENCE: [&str; 8] = [
    "script_group",
    "cell_deps",
    "header_deps",
    "outputs_data",
    "witnesses",
    "capacity_fee_tx_size_cycles",
    "deployment_manifest",
    "builder_plan",
];
const ICKB_REQUIRED_HARDENING_EVIDENCE: [&str; 5] =
    ["mutation_coverage", "deterministic_fuzz_seed", "normalized_fixture_generator", "max_cellscript_cycles", "max_tx_size_bytes"];
pub(super) const CELLSCRIPT_CKB_RPC_URL_ENV: &str = "CELLSCRIPT_CKB_RPC_URL";
const NOVASEAL_CERTIFICATION_PLUGIN: &str = "novaseal-profile-v0";
const NOVASEAL_CERTIFICATION_REPORT_SCHEMA: &str = "cellscript-certification-report-v0.1";
const NOVASEAL_PLUGIN_REPORT_SCHEMA: &str = "novaseal-production-gates-v0.4";
const NOVASEAL_PROFILE_CERTIFICATION_SCHEMA: &str = "novaseal-profile-certification-v0.1";
const NOVASEAL_AGREEMENT_PROFILE: &str = "agreement-profile-v0";
const NOVASEAL_CANONICAL_SCHEMA: &str = "NovaSealCanonicalV0";
const NOVASEAL_PROFILE_CERTIFICATION_GATE: &str = "agreement_profile_public_ecosystem_certification_v0";
const NOVASEAL_LOCAL_V1_DIMENSIONS: &[&str] = &[
    "architecture_and_profile_conformance",
    "planned_profiles_and_business_scenarios",
    "security_audit_coverage",
    "devnet_multi_profile_coverage",
    "multi_business_scenario_coverage",
    "full_stateful_acceptance",
    "wallet_signing_vectors",
    "profile_operator_fixtures",
    "service_builder_fixtures",
    "btc_spv_evidence_adapter",
    "external_attestation_adapter",
    "external_evidence_handoff",
    "local_bip340_tcb_review",
    "local_v1_gate",
];
const NOVASEAL_EXTERNAL_V1_DIMENSIONS: &[&str] = &[
    "external_btc_fiber_endpoint_acceptance",
    "all_profiles_production_completeness",
    "public_shared_cell_dep_attestation",
    "external_bip340_tcb_review_attestation",
    "public_btc_spv_evidence",
    "rwa_legal_registry_review_evidence",
];

#[derive(Debug)]
pub enum Command {
    Build(BuildArgs),
    Test(TestArgs),
    Doc(DocArgs),
    Fmt(FmtArgs),
    Init(InitArgs),
    New(NewArgs),
    Add(AddArgs),
    Remove(RemoveArgs),
    Clean(CleanArgs),
    Repl,
    Check(CheckArgs),
    Metadata(MetadataArgs),
    Expand(ExpandArgs),
    Migrate(MigrateArgs),
    Interface(InterfaceArgs),
    InterfaceDiff(InterfaceDiffArgs),
    Constraints(ConstraintsArgs),
    Abi(AbiArgs),
    SchedulerPlan(SchedulerPlanArgs),
    CkbHash(CkbHashArgs),
    CkbStdCompat(CkbStdCompatArgs),
    Explain(ExplainArgs),
    ExplainProfile(ExplainProfileArgs),
    ExplainProof(ExplainProofArgs),
    ExplainAssumptions(ExplainAssumptionsArgs),
    ExplainGenerics(ExplainGenericsArgs),
    ExplainGraph(ExplainGraphArgs),
    OptReport(OptReportArgs),
    ProofDiff(ProofDiffArgs),
    Profile(ProfileArgs),
    TraceTx(TraceTxArgs),
    AuditBundle(AuditBundleArgs),
    ValidateTx(ValidateTxArgs),
    SolveTx(SolveTxArgs),
    VerifyCkbFixtures(VerifyCkbFixturesArgs),
    DeployPlan(DeployPlanArgs),
    VerifyDeploy(VerifyDeployArgs),
    DiffDeploy(DiffDeployArgs),
    LockDeps(LockDepsArgs),
    ActionBuild(ActionBuildArgs),
    GenBuilder(GenBuilderArgs),
    /// Encode generated entry wrapper witness bytes
    EntryWitness(EntryWitnessArgs),
    Receipt(ReceiptArgs),
    SignReceipt(SignReceiptArgs),
    VerifyReceipt(VerifyReceiptArgs),
    VerifyArtifact(VerifyArtifactArgs),
    ProtocolBundleCheck(ProtocolBundleCheckArgs),
    Run(RunArgs),
    Artifact(ArtifactArgs),
    Publish(PublishArgs),
    Install(InstallArgs),
    RegistryVerify(RegistryVerifyArgs),
    PackageVerify(PackageVerifyArgs),
    RegistryAdd(RegistryAddArgs),
    RegistryEdit(RegistryEditArgs),
    Certify(CertifyArgs),
    Lock(PackageLockArgs),
    Update,
    Info(InfoArgs),
    Login(LoginArgs),
    AuthLogin(AuthCapabilityArgs),
    AuthCapabilityCreate(AuthCapabilityArgs),
    AuthCapabilitySubmit(AuthCapabilitySubmitArgs),
    AuthCapabilityRevoke(AuthCapabilityRevokeArgs),
    AuthReproducerCreate(AuthReproducerCreateArgs),
    AuthNamespaceClaim(AuthNamespaceClaimArgs),
}

#[derive(Debug, Default)]
pub struct BuildArgs {
    pub release: bool,
    pub target: Option<String>,
    pub target_profile: Option<String>,
    pub entry_action: Option<String>,
    pub entry_lock: Option<String>,
    pub artifact: Option<String>,
    pub jobs: Option<usize>,
    pub features: Vec<String>,
    pub all_features: bool,
    pub no_default_features: bool,
    pub locked: bool,
    pub frozen: bool,
    pub offline: bool,
    pub environment: Option<String>,
    pub verbose: bool,
    pub json: bool,
    pub production: bool,
    pub deny_fail_closed: bool,
    pub deny_ckb_runtime: bool,
    pub deny_runtime_obligations: bool,
    pub primitive_compat: Option<String>,
    /// Build a specific workspace member by package name.
    pub package: Option<String>,
    /// Build all workspace members.
    pub workspace: bool,
}

#[derive(Debug, Default)]
pub struct TestArgs {
    pub filter: Option<String>,
    pub backend: Option<String>,
    pub jobs: Option<usize>,
    pub release: bool,
    pub no_run: bool,
    pub nocapture: bool,
    pub fail_fast: bool,
    pub doc: bool,
    pub json: bool,
    pub features: Vec<String>,
    pub all_features: bool,
    pub no_default_features: bool,
    pub locked: bool,
    pub frozen: bool,
    pub offline: bool,
    pub environment: Option<String>,
}

#[derive(Debug, Default)]
pub struct DocArgs {
    pub open: bool,
    pub no_deps: bool,
    pub document_private_items: bool,
    pub output_format: OutputFormat,
    pub json: bool,
}

#[derive(Debug, Default)]
pub struct FmtArgs {
    pub check: bool,
    pub json: bool,
    pub files: Vec<PathBuf>,
}

#[derive(Debug, Default)]
pub struct InitArgs {
    pub name: Option<String>,
    pub path: Option<PathBuf>,
    pub lib: bool,
    pub namespace: Option<String>,
    pub json: bool,
}

#[derive(Debug, Default)]
pub struct NewArgs {
    pub name: String,
    pub path: Option<PathBuf>,
    pub lib: bool,
    pub vcs: String,
    pub json: bool,
}

#[derive(Debug, Default)]
pub struct AddArgs {
    pub crates: Vec<String>,
    pub package: Option<String>,
    pub dev: bool,
    pub build: bool,
    pub git: Option<String>,
    pub path: Option<PathBuf>,
    pub use_environment: Option<String>,
    pub environment_independent: bool,
    pub json: bool,
}

#[derive(Debug, Default)]
pub struct RemoveArgs {
    pub crates: Vec<String>,
    pub dev: bool,
    pub build: bool,
    pub json: bool,
}

#[derive(Debug, Default)]
pub struct CleanArgs {
    pub json: bool,
    /// Also clean incremental compilation cache (.cell/build/cache)
    pub cache: bool,
}

#[derive(Debug, Default)]
pub struct InfoArgs {
    pub json: bool,
}

#[derive(Debug, Default)]
pub struct PackageLockArgs {
    pub json: bool,
}

#[derive(Debug, Default)]
pub struct CheckArgs {
    pub all_targets: bool,
    pub artifact: Option<String>,
    pub target_profile: Option<String>,
    pub features: Vec<String>,
    pub all_features: bool,
    pub no_default_features: bool,
    pub locked: bool,
    pub frozen: bool,
    pub offline: bool,
    pub environment: Option<String>,
    pub json: bool,
    pub production: bool,
    pub deny_fail_closed: bool,
    pub deny_ckb_runtime: bool,
    pub deny_runtime_obligations: bool,
    pub primitive_compat: Option<String>,
    /// Check a specific workspace member by package name.
    pub package: Option<String>,
    /// Check all workspace members.
    pub workspace: bool,
}

#[derive(Debug, Default)]
pub struct MetadataArgs {
    pub input: Option<PathBuf>,
    pub artifact: Option<String>,
    pub output: Option<PathBuf>,
    pub target: Option<String>,
    pub target_profile: Option<String>,
}

#[derive(Debug, Default)]
pub struct ExpandArgs {
    pub input: Option<PathBuf>,
    pub artifact: Option<String>,
    pub output: Option<PathBuf>,
    pub target: Option<String>,
    pub target_profile: Option<String>,
    pub json: bool,
}

#[derive(Debug, Default)]
pub struct MigrateArgs {
    pub input: Option<PathBuf>,
    pub output: Option<PathBuf>,
    pub to: String,
    pub json: bool,
}

#[derive(Debug, Default)]
pub struct InterfaceArgs {
    pub input: Option<PathBuf>,
    pub output: Option<PathBuf>,
    pub target: Option<String>,
    pub target_profile: Option<String>,
}

#[derive(Debug, Default)]
pub struct InterfaceDiffArgs {
    pub old: PathBuf,
    pub new: PathBuf,
    pub output: Option<PathBuf>,
    pub json: bool,
}

#[derive(Debug, Default)]
pub struct ConstraintsArgs {
    pub input: Option<PathBuf>,
    pub output: Option<PathBuf>,
    pub target: Option<String>,
    pub target_profile: Option<String>,
    pub entry_action: Option<String>,
    pub entry_lock: Option<String>,
}

#[derive(Debug, Default)]
pub struct AbiArgs {
    pub input: Option<PathBuf>,
    pub output: Option<PathBuf>,
    pub target: Option<String>,
    pub target_profile: Option<String>,
    pub action: Option<String>,
    pub lock: Option<String>,
}

#[derive(Debug, Default)]
pub struct SchedulerPlanArgs {
    pub input: Option<PathBuf>,
    pub output: Option<PathBuf>,
    pub target: Option<String>,
    pub target_profile: Option<String>,
}

#[derive(Debug, Default)]
pub struct CkbHashArgs {
    pub input: Option<String>,
    pub hex: Option<String>,
    pub file: Option<PathBuf>,
    pub json: bool,
}

#[derive(Debug, Default)]
pub struct CkbStdCompatArgs {
    pub json: bool,
}

#[derive(Debug, Default)]
pub struct ExplainArgs {
    pub code: String,
    pub json: bool,
}

#[derive(Debug, Default)]
pub struct ExplainProfileArgs {
    pub profile: String,
    pub json: bool,
}

#[derive(Debug, Default)]
pub struct ExplainProofArgs {
    pub input: Option<PathBuf>,
    pub target: Option<String>,
    pub target_profile: Option<String>,
    pub json: bool,
}

#[derive(Debug, Default)]
pub struct ExplainAssumptionsArgs {
    pub input: Option<PathBuf>,
    pub target: Option<String>,
    pub target_profile: Option<String>,
    pub json: bool,
}

#[derive(Debug, Default)]
pub struct ExplainGenericsArgs {
    pub input: Option<PathBuf>,
    pub target: Option<String>,
    pub target_profile: Option<String>,
    pub json: bool,
}

#[derive(Debug, Default)]
pub struct ExplainGraphArgs {
    pub input: Option<PathBuf>,
    pub target: Option<String>,
    pub target_profile: Option<String>,
    pub json: bool,
    pub format: Option<String>,
}

#[derive(Debug, Default)]
pub struct OptReportArgs {
    pub input: Option<PathBuf>,
    pub output: Option<PathBuf>,
    pub target: Option<String>,
    pub target_profile: Option<String>,
}

#[derive(Debug, Default)]
pub struct ProofDiffArgs {
    pub old: PathBuf,
    pub new: PathBuf,
    pub json: bool,
}

#[derive(Debug, Default)]
pub struct ProfileArgs {
    pub input: Option<PathBuf>,
    pub entry: Option<String>,
    pub target: Option<String>,
    pub target_profile: Option<String>,
    pub json: bool,
}

#[derive(Debug, Default)]
pub struct TraceTxArgs {
    pub against: PathBuf,
    pub tx: PathBuf,
    pub json: bool,
}

#[derive(Debug, Default)]
pub struct AuditBundleArgs {
    pub input: Option<PathBuf>,
    pub output: Option<PathBuf>,
    pub target: Option<String>,
    pub target_profile: Option<String>,
    pub json: bool,
}

#[derive(Debug, Default)]
pub struct ValidateTxArgs {
    pub against: PathBuf,
    pub tx: PathBuf,
    pub json: bool,
}

#[derive(Debug, Default)]
pub struct SolveTxArgs {
    pub input: Option<PathBuf>,
    pub output: Option<PathBuf>,
    pub target: Option<String>,
    pub target_profile: Option<String>,
    pub json: bool,
}

#[derive(Debug, Default)]
pub struct VerifyCkbFixturesArgs {
    pub manifest: PathBuf,
    pub json: bool,
}

#[derive(Debug, Default)]
pub struct DeployPlanArgs {
    pub input: Option<PathBuf>,
    pub output: Option<PathBuf>,
    pub target: Option<String>,
    pub target_profile: Option<String>,
    pub json: bool,
}

#[derive(Debug, Default)]
pub struct VerifyDeployArgs {
    pub plan: PathBuf,
    pub json: bool,
}

#[derive(Debug, Default)]
pub struct DiffDeployArgs {
    pub old: PathBuf,
    pub new: PathBuf,
    pub json: bool,
}

#[derive(Debug, Default)]
pub struct LockDepsArgs {
    pub input: Option<PathBuf>,
    pub output: Option<PathBuf>,
    pub target: Option<String>,
    pub target_profile: Option<String>,
    pub json: bool,
}

#[derive(Debug, Default)]
pub struct ActionBuildArgs {
    pub input: Option<PathBuf>,
    pub action: Option<String>,
    pub output: Option<PathBuf>,
    pub target: Option<String>,
    pub target_profile: Option<String>,
    pub fabric_intent: bool,
    pub json: bool,
}

#[derive(Debug, Default)]
pub struct GenBuilderArgs {
    pub input: Option<PathBuf>,
    pub artifact: Option<String>,
    pub metadata: Option<PathBuf>,
    pub lockfile: Option<PathBuf>,
    pub deployed: Option<PathBuf>,
    pub deployment_network: Option<String>,
    pub action: Option<String>,
    pub output: Option<PathBuf>,
    pub target: String,
    pub target_profile: Option<String>,
    pub package_name: Option<String>,
    pub json: bool,
}

/// Entry witness encoding arguments
#[derive(Debug, Default)]
pub struct EntryWitnessArgs {
    pub input: Option<PathBuf>,
    pub artifact: Option<String>,
    pub script_hash: Option<String>,
    pub action: Option<String>,
    pub lock: Option<String>,
    pub args: Vec<String>,
    pub output: Option<PathBuf>,
    pub target: Option<String>,
    pub target_profile: Option<String>,
    pub json: bool,
}

#[derive(Debug, Default)]
pub struct ReceiptArgs {
    pub input: Option<PathBuf>,
    pub output: PathBuf,
    pub target: Option<String>,
    pub target_profile: Option<String>,
    pub json: bool,
}

#[derive(Debug, Default)]
pub struct SignReceiptArgs {
    pub receipt: PathBuf,
    pub role: String,
    pub key: String,
    pub output: Option<PathBuf>,
    pub json: bool,
}

#[derive(Debug, Default)]
pub struct VerifyReceiptArgs {
    pub receipt: PathBuf,
    pub metadata: PathBuf,
    pub artifact: PathBuf,
    pub json: bool,
}

#[derive(Debug, Default)]
pub struct VerifyArtifactArgs {
    pub artifact: PathBuf,
    pub metadata: Option<PathBuf>,
    pub lowering_record: Option<PathBuf>,
    pub source_map: Option<PathBuf>,
    pub receipt: Option<PathBuf>,
    pub verify_sources: bool,
    pub json: bool,
    pub expect_target_profile: Option<String>,
    pub expect_artifact_hash: Option<String>,
    pub expect_source_hash: Option<String>,
    pub expect_source_content_hash: Option<String>,
    pub production: bool,
    pub deny_fail_closed: bool,
    pub deny_ckb_runtime: bool,
    pub deny_runtime_obligations: bool,
    pub primitive_compat: Option<String>,
}

#[derive(Debug, Default)]
pub struct ProtocolBundleCheckArgs {
    pub manifest: PathBuf,
    pub output: Option<PathBuf>,
    pub json: bool,
}

#[derive(Debug, Default)]
pub struct RunArgs {
    pub args: Vec<String>,
    pub release: bool,
    pub simulate: bool,
    pub json: bool,
}

#[derive(Debug, Default)]
pub struct PublishArgs {
    pub dry_run: bool,
    pub offline: bool,
    pub allow_dirty: bool,
    pub api_url: Option<String>,
    pub capability_key_id: Option<String>,
    pub authorise: bool,
    pub no_open: bool,
    pub capability_signature: Option<String>,
    pub idempotency_key: Option<String>,
    pub payload: Option<PathBuf>,
    pub source_snapshot: Option<PathBuf>,
    pub artifact_manifest: Option<PathBuf>,
    pub artifact_kind: Option<String>,
    pub print_payload: bool,
    pub json: bool,
}

#[derive(Debug, Default)]
pub struct InstallArgs {
    pub crate_name: Option<String>,
    pub version: Option<String>,
    pub namespace: Option<String>,
    pub git: Option<String>,
    pub path: Option<PathBuf>,
    pub allow_unverified: bool,
    pub allow_quarantined: bool,
}

#[derive(Debug, Default)]
pub struct LoginArgs {
    pub registry: Option<String>,
}

#[derive(Debug, Default)]
pub struct AuthCapabilityArgs {
    pub registry_origin: Option<String>,
    pub principal_type: Option<String>,
    pub principal_id: Option<String>,
    pub capability_pubkey: Option<String>,
    pub scopes: Vec<String>,
    pub expires: Option<String>,
    pub capability_expires_at: Option<String>,
    pub json: bool,
}

#[derive(Debug, Default)]
pub struct AuthCapabilitySubmitArgs {
    pub api_url: Option<String>,
    pub payload: PathBuf,
    pub wallet_signature: PathBuf,
    pub json: bool,
}

#[derive(Debug, Default)]
pub struct AuthCapabilityRevokeArgs {
    pub api_url: Option<String>,
    pub registry_origin: Option<String>,
    pub principal_type: Option<String>,
    pub principal_id: Option<String>,
    pub capability_key_id: Option<String>,
    pub payload: Option<PathBuf>,
    pub wallet_signature: Option<PathBuf>,
    pub reason: Option<String>,
    pub json: bool,
}

#[derive(Debug, Default)]
pub struct AuthReproducerCreateArgs {
    pub builder_id: String,
    pub trust_domain: String,
    pub private_key_output: Option<PathBuf>,
    pub json: bool,
}

#[derive(Debug, Default)]
pub struct AuthNamespaceClaimArgs {
    pub api_url: Option<String>,
    pub namespace: String,
    pub payload: PathBuf,
    pub wallet_signature: PathBuf,
    pub json: bool,
}

#[derive(Debug, Default)]
pub struct RegistryVerifyArgs {
    pub json: bool,
    pub live: bool,
    pub rpc_url: Option<String>,
    pub network: Option<String>,
    pub require_publisher_signature: bool,
    pub require_audit_report: bool,
}

#[derive(Debug, Default)]
pub struct PackageVerifyArgs {
    pub json: bool,
}

#[derive(Debug, Default)]
pub struct RegistryAddArgs {
    pub namespace: String,
    pub name: String,
    pub source: String,
}

#[derive(Debug, Default)]
pub struct RegistryEditArgs {
    pub yank: Option<String>,
    pub reason: Option<String>,
    pub replaced_by: Option<String>,
    pub yanked_at: Option<String>,
}

#[derive(Debug, Default)]
pub struct CertifyArgs {
    pub plugin: String,
    pub repo_root: Option<PathBuf>,
    pub report: Option<PathBuf>,
    pub output: Option<PathBuf>,
    pub json: bool,
    pub require_production: bool,
}

pub struct CommandExecutor;

#[derive(Debug)]
struct CommandOutcome {
    machine: serde_json::Value,
    human_lines: Vec<String>,
}

impl CommandOutcome {
    fn emit(self, json: bool) -> Result<()> {
        if json {
            print_json(&self.machine)
        } else {
            for line in self.human_lines {
                println!("{}", line);
            }
            Ok(())
        }
    }

    fn failure(self, message: impl Into<String>) -> CompileError {
        CompileError::without_span(message).with_details(self.machine)
    }
}

#[derive(Debug, Clone, serde::Serialize)]
struct RunEntryOutcome {
    kind: String,
    name: String,
}

#[derive(Debug, serde::Serialize)]
struct RunOutcome {
    status: &'static str,
    mode: &'static str,
    artifact_format: String,
    entry: Option<RunEntryOutcome>,
    cycles: Option<u64>,
    steps: Option<u64>,
    has_cell_operations: Option<bool>,
    result: Option<String>,
    trace: Vec<String>,
}

impl RunOutcome {
    fn emit(self, json: bool) -> Result<()> {
        if json {
            let value = serde_json::to_value(&self).map_err(|error| {
                CompileError::without_span(format!("failed to serialize run outcome: {}", error))
                    .with_category(crate::error::CompileErrorCategory::Internal)
                    .with_source(error)
            })?;
            return print_json(&value);
        }

        match self.mode {
            "ckb-vm" => {
                println!("{}", "Run complete".green());
                println!("  Artifact format: {}", self.artifact_format);
                if let Some(entry) = self.entry {
                    println!("  Entry: {} {}", entry.kind, entry.name);
                }
                if let Some(cycles) = self.cycles {
                    println!("  Cycles: {}", cycles);
                }
            }
            "simulate" => {
                println!("{}", "Simulate complete".green());
                if let Some(entry) = self.entry {
                    println!("  Entry: {} {}", entry.kind, entry.name);
                }
                if let Some(steps) = self.steps {
                    println!("  Steps: {}", steps);
                }
                match self.has_cell_operations {
                    Some(true) => println!("  Cell operations: {} (simulated)", "yes".yellow()),
                    Some(false) => println!("  Cell operations: none (pure computation)"),
                    None => {}
                }
                if let Some(result) = self.result {
                    println!("  Result: {}", result);
                }
                if !self.trace.is_empty() {
                    println!("  Trace:");
                    for event in self.trace {
                        println!("{}", event);
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }
}

#[cfg(feature = "vm-runner")]
fn run_entry_outcome(metadata: &CompileMetadata) -> Option<RunEntryOutcome> {
    let (kind, name) = metadata.typed_semantics.foundation.entry_contract.exact_entry.split_once(':')?;
    match kind {
        "action" | "lock" => Some(RunEntryOutcome { kind: kind.to_string(), name: name.to_string() }),
        _ => None,
    }
}

fn collect_workspace_incremental_caches(root: &Path, caches: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            continue;
        }
        let name = entry.file_name();
        if name == ".cell" {
            let build = path.join("build");
            let Some(build) = managed_directory_if_present(&build)? else { continue };
            let cache = build.join("cache");
            if let Some(cache) = managed_directory_if_present(&cache)? {
                caches.push(cache);
            }
            continue;
        }
        if matches!(name.to_str(), Some(".git" | "target" | "node_modules")) {
            continue;
        }
        collect_workspace_incremental_caches(&path, caches)?;
    }
    Ok(())
}

fn managed_directory_if_present(path: &Path) -> Result<Option<PathBuf>> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => Err(CompileError::without_span(format!(
            "refusing managed cache path with a symlink or non-directory component: '{}'",
            path.display()
        ))),
        Ok(_) => Ok(Some(path.to_path_buf())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn ensure_workspace_directory_for_removal(workspace_root: &Path, path: &Path) -> Result<PathBuf> {
    let canonical_root = std::fs::canonicalize(workspace_root)?;
    let absolute = if path.is_absolute() { path.to_path_buf() } else { canonical_root.join(path) };
    let canonical_path = std::fs::canonicalize(&absolute)?;
    if !canonical_path.starts_with(&canonical_root) {
        return Err(CompileError::without_span(format!(
            "refusing to clean path outside workspace '{}': '{}'",
            canonical_root.display(),
            canonical_path.display()
        )));
    }
    let relative = absolute
        .strip_prefix(&canonical_root)
        .map_err(|_| CompileError::without_span(format!("refusing non-workspace clean path '{}'", absolute.display())))?;
    let mut cursor = canonical_root;
    for component in relative.components() {
        let std::path::Component::Normal(component) = component else {
            return Err(CompileError::without_span(format!("refusing non-canonical clean path '{}'", path.display())));
        };
        cursor.push(component);
        let metadata = std::fs::symlink_metadata(&cursor)?;
        if metadata.file_type().is_symlink() {
            return Err(CompileError::without_span(format!("refusing to clean through symlink '{}'", cursor.display())));
        }
    }
    let metadata = std::fs::symlink_metadata(&canonical_path)?;
    if !metadata.is_dir() {
        return Err(CompileError::without_span(format!("refusing to clean non-directory path '{}'", path.display())));
    }
    Ok(canonical_path)
}

impl CommandExecutor {
    #[cfg(not(feature = "vm-runner"))]
    fn experimental_command(name: &str, detail: &str) -> Result<()> {
        Err(crate::error::CompileError::without_span(format!("cellc {} is still experimental: {}", name, detail)))
    }

    pub fn execute(cmd: Command) -> Result<()> {
        match cmd {
            Command::Build(args) => Self::build(args),
            Command::Test(args) => Self::test(args),
            Command::Doc(args) => Self::doc(args),
            Command::Fmt(args) => Self::fmt(args),
            Command::Init(args) => Self::init(args),
            Command::New(args) => Self::create_new(args),
            Command::Add(args) => Self::add(args),
            Command::Remove(args) => Self::remove(args),
            Command::Clean(args) => Self::clean(args),
            Command::Repl => Self::repl(),
            Command::Check(args) => Self::check(args),
            Command::Metadata(args) => Self::metadata(args),
            Command::Expand(args) => Self::expand(args),
            Command::Migrate(args) => Self::migrate(args),
            Command::Interface(args) => Self::interface(args),
            Command::InterfaceDiff(args) => Self::interface_diff(args),
            Command::Constraints(args) => Self::constraints(args),
            Command::Abi(args) => Self::abi(args),
            Command::SchedulerPlan(args) => Self::scheduler_plan(args),
            Command::CkbHash(args) => Self::ckb_hash(args),
            Command::CkbStdCompat(args) => Self::ckb_std_compat(args),
            Command::Explain(args) => Self::explain(args),
            Command::ExplainProfile(args) => Self::explain_profile(args),
            Command::ExplainProof(args) => Self::explain_proof(args),
            Command::ExplainAssumptions(args) => Self::explain_assumptions(args),
            Command::ExplainGenerics(args) => Self::explain_generics(args),
            Command::ExplainGraph(args) => Self::explain_graph(args),
            Command::OptReport(args) => Self::opt_report(args),
            Command::ProofDiff(args) => Self::proof_diff(args),
            Command::Profile(args) => Self::profile(args),
            Command::TraceTx(args) => Self::trace_tx(args),
            Command::AuditBundle(args) => Self::audit_bundle(args),
            Command::ValidateTx(args) => Self::validate_tx(args),
            Command::SolveTx(args) => Self::solve_tx(args),
            Command::VerifyCkbFixtures(args) => Self::verify_ckb_fixtures(args),
            Command::DeployPlan(args) => Self::deploy_plan(args),
            Command::VerifyDeploy(args) => Self::verify_deploy(args),
            Command::DiffDeploy(args) => Self::diff_deploy(args),
            Command::LockDeps(args) => Self::lock_deps(args),
            Command::ActionBuild(args) => Self::action_build(args),
            Command::GenBuilder(args) => Self::gen_builder(args),
            Command::EntryWitness(args) => Self::entry_witness(args),
            Command::Receipt(args) => Self::receipt(args),
            Command::SignReceipt(args) => Self::sign_receipt(args),
            Command::VerifyReceipt(args) => Self::verify_receipt(args),
            Command::VerifyArtifact(args) => Self::verify_artifact(args),
            Command::ProtocolBundleCheck(args) => Self::protocol_bundle_check(args),
            Command::Run(args) => Self::run(args),
            Command::Artifact(args) => super::artifact::execute(args),
            Command::Publish(args) => Self::publish(args),
            Command::Install(args) => Self::install(args),
            Command::Lock(args) => Self::lock(args),
            Command::Update => Self::update(),
            Command::Info(args) => Self::info(args),
            Command::Login(args) => Self::login(args),
            Command::AuthLogin(args) | Command::AuthCapabilityCreate(args) => Self::auth_capability(args),
            Command::AuthCapabilitySubmit(args) => Self::auth_capability_submit(args),
            Command::AuthCapabilityRevoke(args) => Self::auth_capability_revoke(args),
            Command::AuthReproducerCreate(args) => Self::auth_reproducer_create(args),
            Command::AuthNamespaceClaim(args) => Self::auth_namespace_claim(args),
            Command::RegistryVerify(args) => Self::registry_verify(args),
            Command::PackageVerify(args) => Self::package_verify(args),
            Command::RegistryAdd(args) => Self::registry_add(args),
            Command::RegistryEdit(args) => Self::registry_edit(args),
            Command::Certify(args) => Self::certify(args),
        }
    }

    fn build(args: BuildArgs) -> Result<()> {
        validate_build_entry_selection(&args)?;
        // Workspace mode: build all members or a specific member.
        if args.workspace || args.package.is_some() {
            return Self::build_workspace(args);
        }
        // Also check if the current directory is a workspace root without explicit flags.
        let ws_root = crate::find_workspace_root(Utf8Path::new("."))?;
        if let Some(ws_root) = ws_root {
            let members = crate::resolve_workspace_members(&ws_root)?;
            if !members.is_empty() {
                // Current dir is a workspace root; build all members.
                let mut ws_args = args;
                ws_args.workspace = true;
                return Self::build_workspace(ws_args);
            }
        }

        let opt_level = if args.release { 3 } else { 1 };
        let input = Utf8Path::new(".");
        let options = CompileOptions {
            edition: crate::CURRENT_EDITION,
            opt_level,
            output: None,
            debug: false,
            target: args.target.clone(),
            target_profile: args.target_profile.clone(),
            primitive_compat: args.primitive_compat.clone(),
        };
        if args.entry_action.is_some() && args.entry_lock.is_some() {
            return Err(crate::error::CompileError::without_span("--entry-action and --entry-lock are mutually exclusive"));
        }
        let policy_args = effective_build_check_args(&args)?;
        let executable_surface_policy = executable_surface_policy(&policy_args);
        let entry_scope = match (args.entry_action.as_deref(), args.entry_lock.as_deref()) {
            (Some(action), None) => Some(CompileEntryScope::Action(action.to_string())),
            (None, Some(lock)) => Some(CompileEntryScope::Lock(lock.to_string())),
            (None, None) => None,
            (Some(_), Some(_)) => unreachable!("validated above"),
        };
        let cache_options = options.clone();
        let resolution_options = build_resolution_options(&args, crate::package::DependencyScope::Runtime);
        let result = crate::package::with_resolution_options(resolution_options, || {
            if let Some(name) = args.artifact.as_deref() {
                crate::compile_path_with_artifact_name(input, options, name, executable_surface_policy)
            } else {
                compile_path_with_executable_surface_policy(input, options, entry_scope, executable_surface_policy)
            }
        })?;
        validate_check_policy(&result.metadata, &policy_args)?;
        let resolved = resolve_input_path(input)?;
        let output_path = default_output_path_for_input(input, &resolved, result.artifact_format)?;
        result.write_to_path(&output_path)?;
        let metadata_path = default_metadata_path_for_artifact(&output_path);
        result.write_metadata_to_path(&metadata_path)?;
        let verified_sidecars = result.write_verified_artifact_sidecars(&output_path)?;

        if !args.frozen {
            refresh_lockfile_from_build(std::path::Path::new("."), &result.metadata)?;
        }
        if args.entry_action.is_none() && args.entry_lock.is_none() && args.artifact.is_none() {
            crate::refresh_incremental_cache_for_input(input, &cache_options, &result)?;
        }

        let policy_verified = policy_args.production
            || policy_args.deny_fail_closed
            || policy_args.deny_ckb_runtime
            || policy_args.deny_runtime_obligations;
        let mut summary = serde_json::json!({
            "status": "ok",
            "artifact": output_path.to_string(),
            "policy_artifact": args.artifact,
            "metadata": metadata_path.to_string(),
            "artifact_format": result.artifact_format.display_name(),
            "opt_level": opt_level,
            "target_profile": result.metadata.target_profile.name.as_str(),
            "artifact_hash": result.metadata.artifact_hash,
            "artifact_size_bytes": result.artifact_bytes.len(),
            "source_hash": result.metadata.source_hash,
            "source_content_hash": result.metadata.source_content_hash,
            "metadata_schema_version": result.metadata.metadata_schema_version,
            "metadata_schema_versions": metadata_schema_versions_json(&result.metadata),
            "compiler_version": result.metadata.compiler_version,
            "standalone_runner_compatible": result.metadata.runtime.standalone_runner_compatible,
            "ckb_runtime_required": result.metadata.runtime.ckb_runtime_required,
            "verifier_obligations": result.metadata.runtime.verifier_obligations.len(),
            "runtime_required_verifier_obligations": runtime_required_obligation_count(&result.metadata),
            "fail_closed_verifier_obligations": fail_closed_obligation_count(&result.metadata),
            "runtime_required_transaction_invariants": runtime_required_transaction_invariant_count(&result.metadata),
            "runtime_required_transaction_invariant_checked_subconditions": runtime_required_transaction_invariant_checked_subcondition_count(&result.metadata),
            "runtime_required_transaction_invariant_checked_subcondition_summaries": transaction_invariant_checked_subcondition_summaries(&result.metadata),
            "transaction_runtime_input_requirements": transaction_runtime_input_requirement_count(&result.metadata),
            "transaction_runtime_input_requirement_summaries": transaction_runtime_input_requirement_summaries(&result.metadata),
            "checked_transaction_runtime_input_requirements": transaction_runtime_input_requirement_count_by_status(&result.metadata, "checked-runtime"),
            "checked_transaction_runtime_input_requirement_summaries": transaction_runtime_input_requirement_summaries_by_status(&result.metadata, "checked-runtime"),
            "runtime_required_transaction_runtime_input_requirements": transaction_runtime_input_requirement_count_by_status(&result.metadata, "runtime-required"),
            "runtime_required_transaction_runtime_input_requirement_summaries": transaction_runtime_input_requirement_summaries_by_status(&result.metadata, "runtime-required"),
            "runtime_required_transaction_runtime_input_blockers": transaction_runtime_input_blocker_count_by_status(&result.metadata, "runtime-required"),
            "runtime_required_transaction_runtime_input_blocker_summaries": transaction_runtime_input_blocker_summaries_by_status(&result.metadata, "runtime-required"),
            "runtime_required_transaction_runtime_input_blocker_classes": transaction_runtime_input_blocker_class_count_by_status(&result.metadata, "runtime-required"),
            "runtime_required_transaction_runtime_input_blocker_class_summaries": transaction_runtime_input_blocker_class_summaries_by_status(&result.metadata, "runtime-required"),
            "checked_pool_invariant_families": checked_pool_invariant_family_count(&result.metadata),
            "runtime_required_pool_invariant_families": runtime_required_pool_invariant_family_count(&result.metadata),
            "runtime_required_pool_invariant_blocker_classes": pool_invariant_family_blocker_class_count(&result.metadata, "runtime-required"),
            "runtime_required_pool_invariant_blocker_class_summaries": pool_invariant_family_blocker_class_summaries(&result.metadata, "runtime-required"),
            "pool_runtime_input_requirements": pool_runtime_input_requirement_count(&result.metadata),
            "pool_runtime_input_requirement_summaries": pool_runtime_input_requirement_summaries(&result.metadata),
            "policy_verified": policy_verified,
            "cache_hit": result.cache_hit,
            "constraints": &result.metadata.constraints,
        });
        if let Some(object) = summary.as_object_mut() {
            object.insert(
                "dependency_lock_mode".to_string(),
                serde_json::json!(if args.frozen {
                    "frozen"
                } else if args.locked {
                    "locked"
                } else {
                    "authoritative"
                }),
            );
            object.insert("dependency_environment".to_string(), serde_json::json!(args.environment.as_deref()));
            object.insert("dependency_offline".to_string(), serde_json::json!(args.offline || args.frozen));
            object.insert("dependency_features".to_string(), serde_json::json!(&args.features));
            object.insert("dependency_all_features".to_string(), serde_json::json!(args.all_features));
            object.insert("dependency_default_features".to_string(), serde_json::json!(!args.no_default_features));
            object
                .insert("lowering_record".to_string(), serde_json::json!(verified_sidecars.as_ref().map(|paths| paths.0.to_string())));
            object.insert("source_map".to_string(), serde_json::json!(verified_sidecars.as_ref().map(|paths| paths.1.to_string())));
        }
        let mut human_lines = vec![
            "Build complete".green().to_string(),
            format!("  Artifact format: {}", result.artifact_format.display_name()),
            format!("  Target profile: {}", result.metadata.target_profile.name),
            format!("  Output: {}", output_path),
            format!("  Metadata: {}", metadata_path),
        ];
        if result.cache_hit {
            human_lines.push(format!("  {}", "(incremental cache hit)".yellow()));
        }
        CommandOutcome { machine: summary, human_lines }.emit(args.json)
    }

    fn build_workspace(args: BuildArgs) -> Result<()> {
        validate_build_entry_selection(&args)?;
        let ws_root = crate::find_workspace_root(Utf8Path::new("."))?.ok_or_else(|| {
            crate::error::CompileError::without_span(
                "no workspace root found; run from a directory containing a [workspace] Cell.toml",
            )
        })?;
        let all_members = crate::resolve_workspace_members(&ws_root)?;
        let members: Vec<_> = if let Some(ref pkg_name) = args.package {
            // Find the specific member by reading its manifest for the package name.
            let mut found = Vec::new();
            for member_dir in &all_members {
                let pm = crate::package::PackageManager::new(member_dir.as_std_path());
                let manifest = pm.read_manifest()?;
                if manifest.package.name == *pkg_name {
                    found.push(member_dir.clone());
                }
            }
            if found.is_empty() {
                return Err(crate::error::CompileError::without_span(format!(
                    "workspace member '{}' not found; available members: {}",
                    pkg_name,
                    all_members.iter().map(|m| m.as_str().to_string()).collect::<Vec<_>>().join(", ")
                )));
            }
            found
        } else {
            all_members
        };

        let opt_level = if args.release { 3 } else { 1 };
        let mut member_results = Vec::new();
        let mut human_lines = Vec::new();
        let mut failure_diagnostics = Vec::new();
        let mut failed = 0;
        let policy_args = effective_build_check_args(&args)?;
        let executable_surface_policy = executable_surface_policy(&policy_args);

        for member_dir in &members {
            let options = CompileOptions {
                edition: crate::CURRENT_EDITION,
                opt_level,
                output: None,
                debug: false,
                target: args.target.clone(),
                target_profile: args.target_profile.clone(),
                primitive_compat: args.primitive_compat.clone(),
            };

            let resolution_options = build_resolution_options(&args, crate::package::DependencyScope::Runtime);
            let entry_scope = match (args.entry_action.as_deref(), args.entry_lock.as_deref()) {
                (Some(action), None) => Some(CompileEntryScope::Action(action.to_string())),
                (None, Some(lock)) => Some(CompileEntryScope::Lock(lock.to_string())),
                (None, None) => None,
                (Some(_), Some(_)) => {
                    return Err(crate::error::CompileError::without_span("--entry-action and --entry-lock are mutually exclusive"));
                }
            };
            let compile_result = crate::package::with_resolution_options(resolution_options, || {
                if let Some(name) = args.artifact.as_deref() {
                    crate::compile_path_with_artifact_name(member_dir, options, name, executable_surface_policy)
                } else {
                    compile_path_with_executable_surface_policy(member_dir, options, entry_scope, executable_surface_policy)
                }
            });

            match compile_result {
                Ok(result) => {
                    if let Err(e) = validate_check_policy(&result.metadata, &policy_args) {
                        failure_diagnostics.push(e.clone().with_file(member_dir.clone()));
                        member_results.push(serde_json::json!({
                            "member": member_dir.as_str(),
                            "status": "failed",
                            "error": e.message,
                        }));
                        failed += 1;
                        continue;
                    }

                    let resolved = resolve_input_path(member_dir)?;
                    let output_path = default_output_path_for_input(member_dir, &resolved, result.artifact_format)?;
                    result.write_to_path(&output_path)?;
                    let metadata_path = default_metadata_path_for_artifact(&output_path);
                    result.write_metadata_to_path(&metadata_path)?;
                    let verified_sidecars = result.write_verified_artifact_sidecars(&output_path)?;

                    member_results.push(serde_json::json!({
                        "member": member_dir.as_str(),
                        "status": "ok",
                        "artifact": output_path.to_string(),
                        "metadata": metadata_path.to_string(),
                        "lowering_record": verified_sidecars.as_ref().map(|paths| paths.0.to_string()),
                        "source_map": verified_sidecars.as_ref().map(|paths| paths.1.to_string()),
                        "artifact_format": result.artifact_format.display_name(),
                        "target_profile": result.metadata.target_profile.name,
                        "artifact_hash": result.metadata.artifact_hash,
                        "artifact_size_bytes": result.artifact_bytes.len(),
                        "cache_hit": result.cache_hit,
                    }));

                    human_lines.push(format!("{} {}", "Built".green(), member_dir));
                }
                Err(e) => {
                    failure_diagnostics.push(e.clone().with_file(member_dir.clone()));
                    member_results.push(serde_json::json!({
                        "member": member_dir.as_str(),
                        "status": "failed",
                        "error": e.message,
                    }));
                    failed += 1;
                }
            }
        }

        if failed > 0 {
            return Err(diagnostics_to_error(&failure_diagnostics).with_details(serde_json::json!({
                "mode": "workspace-build",
                "members": members.len(),
                "succeeded": members.len().saturating_sub(failed),
                "failed": failed,
                "results": member_results,
            })));
        }

        // Write workspace-level Cell.lock at the workspace root.
        let mut lockfile = Lockfile::read_from_root(ws_root.as_std_path())?.unwrap_or_else(Lockfile::new);
        // Merge build hashes from each successfully built member.
        for res in &member_results {
            if res["status"].as_str() == Some("ok") {
                let member_name = res["member"].as_str().unwrap_or("unknown");
                let artifact_hash = res.get("artifact_hash").and_then(|v| v.as_str()).unwrap_or("");
                if !artifact_hash.is_empty() {
                    lockfile.dependencies.insert(
                        member_name.to_string(),
                        crate::package::LockedDependency {
                            name: member_name.to_string(),
                            namespace: None,
                            version: String::new(),
                            source: crate::package::LockedSource::Path { path: member_name.to_string() },
                            source_hash: Some(artifact_hash.to_string()),
                            manifest_digest: "workspace-member-artifact".to_string(),
                            dependencies: BTreeMap::new(),
                            build: None,
                        },
                    );
                }
            }
        }
        lockfile.write_to_root(ws_root.as_std_path())?;

        CommandOutcome {
            machine: serde_json::json!({
                "status": "ok",
                "mode": "workspace-build",
                "members": members.len(),
                "succeeded": members.len(),
                "failed": 0,
                "results": member_results,
            }),
            human_lines: {
                human_lines.push(format!("Workspace build complete: {} members", members.len()).green().to_string());
                human_lines
            },
        }
        .emit(args.json)
    }

    fn test(args: TestArgs) -> Result<()> {
        let options = test_resolution_options(&args);
        crate::package::with_resolution_options(options, || Self::test_inner(args))
    }

    fn test_inner(args: TestArgs) -> Result<()> {
        let doc_output = if args.doc {
            Some(Self::generate_docs(&DocArgs { output_format: OutputFormat::Markdown, ..Default::default() })?)
        } else {
            None
        };

        let mut test_inputs = collect_cell_files(Path::new("tests"))?;
        let mut scenario_inputs = super::test_runner::collect_scenario_files(Path::new("tests"))?;
        if let Some(filter) = &args.filter {
            test_inputs.retain(|path| path.to_string_lossy().contains(filter));
            scenario_inputs.retain(|path| path.to_string_lossy().contains(filter));
        }
        test_inputs.sort();
        scenario_inputs.sort();
        let backends = if args.no_run {
            Vec::new()
        } else {
            let backend = args.backend.as_deref().ok_or_else(|| {
                crate::error::CompileError::without_span("cellc test requires --backend simulator|ckb-vm|all unless --no-run is used")
            })?;
            if scenario_inputs.is_empty() {
                return Err(crate::error::CompileError::without_span(
                    "cellc test cannot pass without an executable *.scenario.json fixture; use --no-run for compile-only checks",
                ));
            }
            super::test_runner::TestBackend::parse(backend)?
        };

        if test_inputs.is_empty() {
            compile_path(
                ".",
                CompileOptions {
                    edition: crate::CURRENT_EDITION,
                    opt_level: 0,
                    output: None,
                    debug: false,
                    target: None,
                    target_profile: None,
                    primitive_compat: None,
                },
            )?;
            let mut human_lines = Vec::new();
            if let Some(output) = &doc_output {
                human_lines.push("Documentation generated".green().to_string());
                human_lines.push(format!("  Output: {}", output.display()));
            }
            human_lines.push("Test compile complete".green().to_string());
            human_lines.push("  Package check: passed".to_string());
            human_lines.push("  Test files: 0".to_string());
            if !args.no_run {
                human_lines.push("  Execution: skipped; no CellScript test files were found".to_string());
            }
            return CommandOutcome {
                machine: serde_json::json!({
                    "status": "ok",
                    "package_check": "passed",
                    "test_files": 0,
                    "passed": 0,
                    "failed": 0,
                    "fail_fast": args.fail_fast,
                    "no_run": args.no_run,
                    "execution": if args.no_run { "disabled" } else { "skipped-no-test-files" },
                    "docs_generated": args.doc,
                    "doc_output": doc_output.as_ref().map(|path| path.display().to_string()),
                    "scenario_files": scenario_inputs.len(),
                    "tests": [],
                    "scenarios": [],
                }),
                human_lines,
            }
            .emit(args.json);
        }

        let mut passed = 0usize;
        let mut failures = Vec::new();
        let mut test_reports = Vec::new();
        for input in &test_inputs {
            let utf8 = Utf8Path::from_path(input)
                .ok_or_else(|| crate::error::CompileError::without_span(format!("path '{}' is not valid UTF-8", input.display())))?;
            if args.nocapture && !args.json {
                println!("  Testing {}", utf8);
            }

            let expectation = read_test_expectation(input)?;
            let result = compile_path_with_executable_surface_policy(
                utf8,
                CompileOptions {
                    edition: crate::CURRENT_EDITION,
                    opt_level: 0,
                    output: None,
                    debug: false,
                    target: expectation.target.clone(),
                    target_profile: None,
                    primitive_compat: None,
                },
                None,
                if expectation.production || expectation.deny_fail_closed {
                    ExecutableSurfacePolicy::DenyFailClosed
                } else {
                    ExecutableSurfacePolicy::AllowFailClosed
                },
            )
            .and_then(|result| {
                let policy_args = expectation.check_args();
                validate_check_policy(&result.metadata, &policy_args)?;
                Ok(result)
            });
            match evaluate_compile_test_result(utf8, &expectation, result) {
                Ok(()) => {
                    passed += 1;
                    test_reports.push(serde_json::json!({
                        "path": utf8.to_string(),
                        "status": "passed",
                        "target": expectation.target,
                    }));
                }
                Err(error) => {
                    let message = error.into_message();
                    test_reports.push(serde_json::json!({
                        "path": utf8.to_string(),
                        "status": "failed",
                        "error": message,
                        "target": expectation.target,
                    }));
                    failures.push(message);
                    if args.fail_fast {
                        break;
                    }
                }
            }
        }

        if !failures.is_empty() {
            return Err(crate::error::CompileError::without_span(format!("test failed:\n  - {}", failures.join("\n  - ")))
                .with_details(serde_json::json!({
                    "mode": "test",
                    "test_files": test_inputs.len(),
                    "passed": passed,
                    "failed": failures.len(),
                    "fail_fast": args.fail_fast,
                    "no_run": args.no_run,
                    "tests": test_reports,
                })));
        }

        let mut scenario_reports = Vec::new();
        let mut scenario_failures = Vec::new();
        if !args.no_run {
            for scenario in &scenario_inputs {
                for backend in &backends {
                    match super::test_runner::run_scenario(scenario, *backend) {
                        Ok(report) => scenario_reports.push(report),
                        Err(error) => {
                            let message = format!("{}: {}", scenario.display(), error);
                            scenario_reports.push(serde_json::json!({
                                "schema": "cellscript-test-report-v1",
                                "status": "failed",
                                "scenario_path": scenario.to_string_lossy(),
                                "error": error.to_string(),
                            }));
                            scenario_failures.push(message);
                            if args.fail_fast {
                                break;
                            }
                        }
                    }
                }
                if args.fail_fast && !scenario_failures.is_empty() {
                    break;
                }
            }
        }
        if !scenario_failures.is_empty() {
            return Err(crate::error::CompileError::without_span(format!(
                "scenario test failed:\n  - {}",
                scenario_failures.join("\n  - ")
            ))
            .with_details(serde_json::json!({
                "mode": "test",
                "compile_test_files": test_inputs.len(),
                "scenario_files": scenario_inputs.len(),
                "backend": args.backend,
                "scenario_runs_passed": scenario_reports.len().saturating_sub(scenario_failures.len()),
                "scenario_runs_failed": scenario_failures.len(),
                "scenarios": scenario_reports,
            })));
        }

        let mut human_lines = Vec::new();
        if let Some(output) = &doc_output {
            human_lines.push("Documentation generated".green().to_string());
            human_lines.push(format!("  Output: {}", output.display()));
        }
        human_lines.push(if args.no_run { "Test compile complete" } else { "Test execution complete" }.green().to_string());
        human_lines.push(format!("  Compiled {} test file(s)", passed));
        if args.no_run {
            human_lines.push("  Execution: disabled by --no-run".to_string());
        } else {
            human_lines.push(format!(
                "  Executed {} scenario/backend run(s) with {}",
                scenario_reports.len(),
                args.backend.as_deref().unwrap_or("unknown")
            ));
        }
        CommandOutcome {
            machine: serde_json::json!({
                "status": "ok",
                "package_check": "not-run",
                "test_files": test_inputs.len(),
                "passed": passed,
                "failed": 0,
                "fail_fast": args.fail_fast,
                "no_run": args.no_run,
                "execution": if args.no_run { "disabled" } else { "executed" },
                "backend": args.backend,
                "scenario_files": scenario_inputs.len(),
                "scenario_runs": scenario_reports.len(),
                "docs_generated": args.doc,
                "doc_output": doc_output.as_ref().map(|path| path.display().to_string()),
                "tests": test_reports,
                "scenarios": scenario_reports,
            }),
            human_lines,
        }
        .emit(args.json)
    }

    fn doc(args: DocArgs) -> Result<()> {
        let output = Self::generate_docs(&args)?;
        let output_size_bytes = std::fs::metadata(&output).map(|metadata| metadata.len()).unwrap_or(0);

        let outcome = CommandOutcome {
            machine: serde_json::json!({
                "status": "ok",
                "format": display_doc_output_format(&args.output_format),
                "output": output.display().to_string(),
                "output_size_bytes": output_size_bytes,
                "opened": args.open,
            }),
            human_lines: vec!["Documentation generated".green().to_string(), format!("  Output: {}", output.display())],
        };

        if args.open {
            let _ = std::process::Command::new("open").arg(&output).status();
        }

        outcome.emit(args.json)
    }

    fn generate_docs(args: &DocArgs) -> Result<PathBuf> {
        let modules = load_modules_for_input(".")?;
        let compile_result = compile_path(
            ".",
            CompileOptions {
                edition: crate::CURRENT_EDITION,
                opt_level: 0,
                output: None,
                debug: false,
                target: None,
                target_profile: None,
                primitive_compat: None,
            },
        )?;
        let mut generator = DocGenerator::new(args.output_format);
        for module in &modules {
            generator.add_module(&module.ast);
        }
        generator.set_compile_metadata(&compile_result.metadata);
        let docs = generator.generate()?;
        let output = match args.output_format {
            OutputFormat::Html => PathBuf::from("docs/cellscript-api.html"),
            OutputFormat::Markdown => PathBuf::from("docs/cellscript-api.md"),
            OutputFormat::Json => PathBuf::from("docs/cellscript-api.json"),
        };
        if let Some(parent) = output.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&output, docs)?;

        Ok(output)
    }

    fn fmt(args: FmtArgs) -> Result<()> {
        let modules = if args.files.is_empty() {
            load_modules_for_input(".")?
        } else {
            let mut modules = Vec::new();
            for path in &args.files {
                let utf8 = Utf8Path::from_path(path).ok_or_else(|| {
                    crate::error::CompileError::without_span(format!("path '{}' is not valid UTF-8", path.display()))
                })?;
                modules.extend(load_modules_for_input(utf8)?);
            }
            modules
        };

        let mut changed = Vec::new();
        for module in modules {
            let formatted = format_default(&module.ast)?;
            if formatted != module.source {
                changed.push(module.path.clone());
                if !args.check {
                    std::fs::write(&module.path, formatted)?;
                }
            }
        }
        let changed_files = changed.iter().map(|path| path.as_str()).collect::<Vec<_>>();

        if args.check {
            if changed.is_empty() {
                CommandOutcome {
                    machine: serde_json::json!({
                        "status": "ok",
                        "mode": "check",
                        "changed": 0,
                        "changed_files": changed_files,
                    }),
                    human_lines: vec!["Formatting is clean".green().to_string()],
                }
                .emit(args.json)
            } else {
                let outcome = CommandOutcome {
                    machine: serde_json::json!({
                        "status": "failed",
                        "mode": "check",
                        "changed": changed.len(),
                        "changed_files": changed_files,
                    }),
                    human_lines: Vec::new(),
                };
                Err(outcome.failure(format!(
                    "format check failed for {} file(s): {}",
                    changed.len(),
                    changed.iter().map(|path| path.as_str()).collect::<Vec<_>>().join(", ")
                )))
            }
        } else {
            CommandOutcome {
                machine: serde_json::json!({
                    "status": "ok",
                    "mode": "write",
                    "changed": changed.len(),
                    "changed_files": changed_files,
                }),
                human_lines: vec!["Formatting complete".green().to_string(), format!("  Updated {} file(s)", changed.len())],
            }
            .emit(args.json)
        }
    }

    fn init(args: InitArgs) -> Result<()> {
        let path = args.path.unwrap_or_else(|| PathBuf::from("."));
        let name = args.name.unwrap_or_else(|| path.file_name().unwrap_or_default().to_string_lossy().to_string());

        let pm = PackageManager::new(&path);
        if args.lib {
            pm.init_library(&name)?;
        } else {
            pm.init(&name)?;
        }
        if let Some(namespace) = &args.namespace {
            let mut manifest = pm.read_manifest()?;
            manifest.package.namespace = Some(namespace.clone());
            pm.write_manifest(&manifest)?;
        }

        let entry = if args.lib { "src/lib.cell" } else { "src/main.cell" };
        CommandOutcome {
            machine: serde_json::json!({
                "status": "ok",
                "kind": if args.lib { "library" } else { "binary" },
                "package": name,
                "path": path.display().to_string(),
                "manifest": path.join("Cell.toml").display().to_string(),
                "entry": entry,
                "namespace": args.namespace,
                "created_files": [
                    path.join("Cell.toml").display().to_string(),
                    path.join(entry).display().to_string(),
                    path.join(".gitignore").display().to_string(),
                ],
            }),
            human_lines: vec![
                "Created package successfully".green().to_string(),
                "  To get started:".to_string(),
                format!("    cd {}", path.display()),
                "    cellc build".to_string(),
            ],
        }
        .emit(args.json)
    }

    fn create_new(args: NewArgs) -> Result<()> {
        let path = args.path.unwrap_or_else(|| PathBuf::from(&args.name));
        ensure_new_package_destination(&path)?;

        let pm = PackageManager::new(&path);
        if args.lib {
            pm.init_library(&args.name)?;
        } else {
            pm.init(&args.name)?;
        }

        let git_initialized = match args.vcs.as_str() {
            "git" => init_git_repo(&path)?,
            "none" => false,
            other => {
                return Err(crate::error::CompileError::without_span(format!("unsupported VCS '{}'; expected 'git' or 'none'", other)))
            }
        };

        let entry = if args.lib { "src/lib.cell" } else { "src/main.cell" };
        CommandOutcome {
            machine: serde_json::json!({
                "status": "ok",
                "command": "new",
                "kind": if args.lib { "library" } else { "binary" },
                "package": args.name,
                "path": path.display().to_string(),
                "manifest": path.join("Cell.toml").display().to_string(),
                "entry": entry,
                "vcs": args.vcs,
                "git_initialized": git_initialized,
                "created_files": [
                    path.join("Cell.toml").display().to_string(),
                    path.join(entry).display().to_string(),
                    path.join(".gitignore").display().to_string(),
                ],
            }),
            human_lines: vec![
                "Created package successfully".green().to_string(),
                "  To get started:".to_string(),
                format!("    cd {}", path.display()),
                "    cellc build".to_string(),
            ],
        }
        .emit(args.json)
    }

    fn add(args: AddArgs) -> Result<()> {
        validate_dependency_target_flags(args.dev, args.build)?;
        if args.git.is_some() && args.path.is_some() {
            return Err(crate::error::CompileError::without_span("cellc add accepts either --git or --path, not both"));
        }
        if args.package.is_some() && args.crates.len() != 1 {
            return Err(crate::error::CompileError::without_span("cellc add --package requires exactly one local dependency alias"));
        }
        if args.use_environment.is_some() && args.environment_independent {
            return Err(crate::error::CompileError::without_span(
                "cellc add accepts either --use-environment or --environment-independent, not both",
            ));
        }

        let pm = PackageManager::new(".");
        let mut manifest = pm.read_manifest()?;
        let dependency = dependency_from_add_args(&args);
        let target = dependency_target_label(args.dev, args.build);
        let mut added = Vec::new();

        for crate_name in &args.crates {
            validate_not_self_dependency(crate_name, &dependency, &manifest)?;
            dependency_map_mut(&mut manifest, args.dev, args.build).insert(crate_name.clone(), dependency.clone());
            added.push(crate_name.clone());
        }

        pm.write_manifest(&manifest)?;
        refresh_lockfile_from_manifest(Path::new("."))?;

        CommandOutcome {
            machine: serde_json::json!({
                "status": "ok",
                "target": target,
                "added": added,
                "dependency": dependency,
            }),
            human_lines: vec!["Dependencies added successfully".green().to_string()],
        }
        .emit(args.json)
    }

    fn remove(args: RemoveArgs) -> Result<()> {
        validate_dependency_target_flags(args.dev, args.build)?;
        let pm = PackageManager::new(".");
        let mut manifest = pm.read_manifest()?;
        let target = dependency_target_label(args.dev, args.build);
        let mut removed = Vec::new();
        let mut missing = Vec::new();

        for crate_name in &args.crates {
            if dependency_map_mut(&mut manifest, args.dev, args.build).remove(crate_name).is_some() {
                removed.push(crate_name.clone());
            } else {
                missing.push(crate_name.clone());
            }
        }

        pm.write_manifest(&manifest)?;
        if !removed.is_empty() {
            refresh_lockfile_from_manifest(Path::new("."))?;
        }

        CommandOutcome {
            machine: serde_json::json!({
                "status": "ok",
                "target": target,
                "removed": removed,
                "missing": missing,
            }),
            human_lines: vec!["Dependencies removed successfully".green().to_string()],
        }
        .emit(args.json)
    }

    fn clean(args: CleanArgs) -> Result<()> {
        let workspace_root = std::fs::canonicalize(".")?;
        let mut paths = vec![PathBuf::from("target"), PathBuf::from(".cell/cache")];
        if args.cache {
            collect_workspace_incremental_caches(Path::new("."), &mut paths)?;
        }
        paths.sort();
        paths.dedup();
        let mut removed_paths = Vec::new();

        for path in paths {
            if path.exists() {
                let removable = ensure_workspace_directory_for_removal(&workspace_root, &path)?;
                std::fs::remove_dir_all(removable)?;
                removed_paths.push(path.to_string_lossy().into_owned());
            }
        }

        CommandOutcome {
            machine: serde_json::json!({
                "status": "ok",
                "removed": removed_paths.len(),
                "removed_paths": removed_paths,
            }),
            human_lines: vec!["Clean complete".green().to_string()],
        }
        .emit(args.json)
    }

    fn repl() -> Result<()> {
        crate::repl::run_repl().map_err(|e| crate::error::CompileError::without_span(e.to_string()))
    }

    fn check(args: CheckArgs) -> Result<()> {
        // Workspace mode: check all members or a specific member.
        if args.workspace || args.package.is_some() {
            return Self::check_workspace(args);
        }
        let ws_root = crate::find_workspace_root(Utf8Path::new("."))?;
        if let Some(ws_root) = ws_root {
            let members = crate::resolve_workspace_members(&ws_root)?;
            if !members.is_empty() {
                let mut ws_args = args;
                ws_args.workspace = true;
                return Self::check_workspace(ws_args);
            }
        }

        let args = effective_check_args(args)?;
        let requested_profile = effective_check_target_profile(&args)?;
        let compile_target_profile = compile_target_profile_for_check(requested_profile);
        let mut checked_targets = Vec::new();
        let mut checked_target_json = Vec::new();
        let targets: Vec<Option<&'static str>> =
            if args.all_targets { vec![Some("riscv64-asm"), Some("riscv64-elf")] } else { vec![None] };

        for target in targets {
            let compile_options = CompileOptions {
                edition: crate::CURRENT_EDITION,
                opt_level: 0,
                output: None,
                debug: false,
                target: target.map(str::to_string),
                target_profile: compile_target_profile.clone(),
                primitive_compat: args.primitive_compat.clone(),
            };
            let resolution_options = check_resolution_options(&args, crate::package::DependencyScope::Runtime);
            let result = match crate::package::with_resolution_options(resolution_options, || {
                if let Some(name) = args.artifact.as_deref() {
                    crate::compile_path_with_artifact_name(".", compile_options.clone(), name, executable_surface_policy(&args))
                } else {
                    compile_path_with_executable_surface_policy(".", compile_options.clone(), None, executable_surface_policy(&args))
                }
            }) {
                Ok(result) => result,
                Err(error) if args.artifact.is_some() => return Err(error),
                Err(error) => {
                    let diagnostics = compile_failure_diagnostics(Utf8Path::new("."), compile_options, error);
                    return Err(diagnostics_to_error(&diagnostics));
                }
            };
            validate_check_policy(&result.metadata, &args)?;
            let target_profile_policy_violations =
                target_profile_policy_violations(&result.metadata, result.artifact_format, requested_profile);
            if !target_profile_policy_violations.is_empty() {
                return Err(crate::error::CompileError::without_span(format!(
                    "target profile policy failed for '{}':\n  - {}",
                    requested_profile.name(),
                    target_profile_policy_violations.join("\n  - ")
                )));
            }
            let target_label = match target {
                Some(target) => format!("{} ({})", target, result.artifact_format.display_name()),
                None => format!("package default ({})", result.artifact_format.display_name()),
            };
            let requested_profile_name = requested_profile.name();
            checked_target_json.push(serde_json::json!({
                "requested_target": target.unwrap_or("package-default"),
                "artifact_format": result.artifact_format.display_name(),
                "target_profile": requested_profile_name,
                "compiled_target_profile": result.metadata.target_profile.name.as_str(),
                "target_profile_policy_violations": target_profile_policy_violations,
                "metadata_schema_version": result.metadata.metadata_schema_version,
                "metadata_schema_versions": metadata_schema_versions_json(&result.metadata),
                "compiler_version": result.metadata.compiler_version,
                "standalone_runner_compatible": result.metadata.runtime.standalone_runner_compatible,
                "ckb_runtime_required": result.metadata.runtime.ckb_runtime_required,
                "fail_closed_runtime_features": result.metadata.runtime.fail_closed_runtime_features,
                "verifier_obligations": result.metadata.runtime.verifier_obligations.len(),
                "runtime_required_verifier_obligations": runtime_required_obligation_count(&result.metadata),
                "fail_closed_verifier_obligations": fail_closed_obligation_count(&result.metadata),
                "runtime_required_transaction_invariants": runtime_required_transaction_invariant_count(&result.metadata),
                "runtime_required_transaction_invariant_checked_subconditions": runtime_required_transaction_invariant_checked_subcondition_count(&result.metadata),
                "runtime_required_transaction_invariant_checked_subcondition_summaries": transaction_invariant_checked_subcondition_summaries(&result.metadata),
                "transaction_runtime_input_requirements": transaction_runtime_input_requirement_count(&result.metadata),
                "transaction_runtime_input_requirement_summaries": transaction_runtime_input_requirement_summaries(&result.metadata),
                "checked_transaction_runtime_input_requirements": transaction_runtime_input_requirement_count_by_status(&result.metadata, "checked-runtime"),
                "checked_transaction_runtime_input_requirement_summaries": transaction_runtime_input_requirement_summaries_by_status(&result.metadata, "checked-runtime"),
                "runtime_required_transaction_runtime_input_requirements": transaction_runtime_input_requirement_count_by_status(&result.metadata, "runtime-required"),
                "runtime_required_transaction_runtime_input_requirement_summaries": transaction_runtime_input_requirement_summaries_by_status(&result.metadata, "runtime-required"),
                "runtime_required_transaction_runtime_input_blockers": transaction_runtime_input_blocker_count_by_status(&result.metadata, "runtime-required"),
                "runtime_required_transaction_runtime_input_blocker_summaries": transaction_runtime_input_blocker_summaries_by_status(&result.metadata, "runtime-required"),
                "runtime_required_transaction_runtime_input_blocker_classes": transaction_runtime_input_blocker_class_count_by_status(&result.metadata, "runtime-required"),
                "runtime_required_transaction_runtime_input_blocker_class_summaries": transaction_runtime_input_blocker_class_summaries_by_status(&result.metadata, "runtime-required"),
                "checked_pool_invariant_families": checked_pool_invariant_family_count(&result.metadata),
                "runtime_required_pool_invariant_families": runtime_required_pool_invariant_family_count(&result.metadata),
                "runtime_required_pool_invariant_blocker_classes": pool_invariant_family_blocker_class_count(&result.metadata, "runtime-required"),
                "runtime_required_pool_invariant_blocker_class_summaries": pool_invariant_family_blocker_class_summaries(&result.metadata, "runtime-required"),
                "pool_runtime_input_requirements": pool_runtime_input_requirement_count(&result.metadata),
                "pool_runtime_input_requirement_summaries": pool_runtime_input_requirement_summaries(&result.metadata),
                "constraints": &result.metadata.constraints,
            }));
            checked_targets.push(target_label);
        }

        let policy_verified = args.production || args.deny_fail_closed || args.deny_ckb_runtime;
        let policy_verified = policy_verified || args.deny_runtime_obligations;
        let summary = serde_json::json!({
            "status": "ok",
            "checked_targets": checked_target_json,
            "policy_artifact": args.artifact,
            "all_targets": args.all_targets,
            "policy_verified": policy_verified,
            "policy": {
                "production": args.production,
                "deny_fail_closed": args.deny_fail_closed,
                "deny_ckb_runtime": args.deny_ckb_runtime,
                "deny_runtime_obligations": args.deny_runtime_obligations,
            },
        });
        let mut human_lines = vec!["Check succeeded".green().to_string(), format!("  Target profile: {}", requested_profile.name())];
        human_lines.extend(checked_targets.into_iter().map(|target| format!("  Checked: {}", target)));
        CommandOutcome { machine: summary, human_lines }.emit(args.json)
    }

    fn check_workspace(args: CheckArgs) -> Result<()> {
        let args = effective_check_args(args)?;
        let ws_root = crate::find_workspace_root(Utf8Path::new("."))?.ok_or_else(|| {
            crate::error::CompileError::without_span(
                "no workspace root found; run from a directory containing a [workspace] Cell.toml",
            )
        })?;
        let all_members = crate::resolve_workspace_members(&ws_root)?;
        let members: Vec<_> = if let Some(ref pkg_name) = args.package {
            let mut found = Vec::new();
            for member_dir in &all_members {
                let pm = crate::package::PackageManager::new(member_dir.as_std_path());
                let manifest = pm.read_manifest()?;
                if manifest.package.name == *pkg_name {
                    found.push(member_dir.clone());
                }
            }
            if found.is_empty() {
                return Err(crate::error::CompileError::without_span(format!("workspace member '{}' not found", pkg_name)));
            }
            found
        } else {
            all_members
        };

        let mut member_results = Vec::new();
        let mut human_lines = Vec::new();
        let mut failure_diagnostics = Vec::new();
        let mut failed = 0;

        for member_dir in &members {
            let compile_options = CompileOptions {
                edition: crate::CURRENT_EDITION,
                opt_level: 0,
                output: None,
                debug: false,
                target: None,
                target_profile: args.target_profile.clone(),
                primitive_compat: args.primitive_compat.clone(),
            };
            let resolution_options = check_resolution_options(&args, crate::package::DependencyScope::Runtime);
            let compile_result = crate::package::with_resolution_options(resolution_options, || {
                if let Some(name) = args.artifact.as_deref() {
                    crate::compile_path_with_artifact_name(member_dir, compile_options, name, executable_surface_policy(&args))
                } else {
                    compile_path_with_executable_surface_policy(member_dir, compile_options, None, executable_surface_policy(&args))
                }
            });

            match compile_result {
                Ok(result) => {
                    if let Err(error) = validate_check_policy(&result.metadata, &args) {
                        failure_diagnostics.push(error.clone().with_file(member_dir.clone()));
                        member_results.push(serde_json::json!({
                            "member": member_dir.as_str(),
                            "status": "failed",
                            "error": error.message,
                        }));
                        failed += 1;
                        continue;
                    }
                    member_results.push(serde_json::json!({
                        "member": member_dir.as_str(),
                        "status": "ok",
                        "artifact_format": result.artifact_format.display_name(),
                        "target_profile": result.metadata.target_profile.name,
                    }));
                    human_lines.push(format!("{} {}", "Checked".green(), member_dir));
                }
                Err(e) => {
                    failure_diagnostics.push(e.clone().with_file(member_dir.clone()));
                    member_results.push(serde_json::json!({
                        "member": member_dir.as_str(),
                        "status": "failed",
                        "error": e.message,
                    }));
                    failed += 1;
                }
            }
        }

        if failed > 0 {
            return Err(diagnostics_to_error(&failure_diagnostics).with_details(serde_json::json!({
                "mode": "workspace-check",
                "members": members.len(),
                "succeeded": members.len().saturating_sub(failed),
                "failed": failed,
                "results": member_results,
            })));
        }
        CommandOutcome {
            machine: serde_json::json!({
                "status": "ok",
                "mode": "workspace-check",
                "members": members.len(),
                "succeeded": members.len(),
                "failed": 0,
                "results": member_results,
            }),
            human_lines: {
                human_lines.push(format!("Workspace check complete: {} members", members.len()).green().to_string());
                human_lines
            },
        }
        .emit(args.json)
    }

    fn metadata(args: MetadataArgs) -> Result<()> {
        let input_path = args.input.unwrap_or_else(|| PathBuf::from("."));
        let input = Utf8Path::from_path(&input_path)
            .ok_or_else(|| crate::error::CompileError::without_span(format!("path '{}' is not valid UTF-8", input_path.display())))?;
        let options = CompileOptions {
            edition: crate::CURRENT_EDITION,
            opt_level: 0,
            output: None,
            debug: false,
            target: args.target,
            target_profile: args.target_profile,
            primitive_compat: None,
        };
        let metadata = if let Some(name) = args.artifact.as_deref() {
            crate::artifact::compile_path_artifact_metadata(input, options, name)?
        } else {
            match compile_path(input, options.clone()) {
                Ok(result) => result.metadata,
                Err(error) => return Err(diagnostics_to_error(&compile_failure_diagnostics(input, options, error))),
            }
        };
        let json = serde_json::to_string_pretty(&metadata)
            .map_err(|error| crate::error::CompileError::without_span(format!("failed to serialize metadata: {}", error)))?;

        if let Some(output_path) = args.output.as_ref() {
            if let Some(parent) = output_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(output_path, json)?;
            println!("{}", "Metadata generated".green());
            println!("  Output: {}", output_path.display());
        } else {
            println!("{}", json);
        }
        Ok(())
    }

    fn expand(args: ExpandArgs) -> Result<()> {
        let input_path = args.input.unwrap_or_else(|| PathBuf::from("."));
        let input = Utf8Path::from_path(&input_path)
            .ok_or_else(|| crate::error::CompileError::without_span(format!("path '{}' is not valid UTF-8", input_path.display())))?;
        let options = CompileOptions {
            edition: crate::CURRENT_EDITION,
            opt_level: 0,
            output: None,
            debug: false,
            target: args.target,
            target_profile: args.target_profile,
            primitive_compat: None,
        };
        let metadata = if let Some(name) = args.artifact.as_deref() {
            crate::artifact::compile_path_artifact_metadata(input, options, name)?
        } else {
            match compile_path(input, options.clone()) {
                Ok(result) => result.metadata,
                Err(error) => return Err(diagnostics_to_error(&compile_failure_diagnostics(input, options, error))),
            }
        };
        let rendered = if args.json {
            serde_json::to_string_pretty(&metadata.typed_semantics.foundation)
                .map_err(|error| CompileError::without_span(format!("failed to serialize semantic foundation: {error}")))?
        } else {
            crate::semantic_expansion::render(&metadata)?
        };
        if let Some(output_path) = args.output.as_ref() {
            if let Some(parent) = output_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(output_path, rendered)?;
            if !args.json {
                println!("{}", "Canonical semantic expansion generated".green());
                println!("  Output: {}", output_path.display());
            }
        } else {
            println!("{}", rendered);
        }
        Ok(())
    }

    fn migrate(args: MigrateArgs) -> Result<()> {
        if args.to != "2027" {
            return Err(CompileError::without_span(format!(
                "unsupported migration target '{}'; the experimental migration target is 2027",
                args.to
            )));
        }
        let input_path = args.input.unwrap_or_else(|| PathBuf::from("."));
        let input = Utf8Path::from_path(&input_path)
            .ok_or_else(|| CompileError::without_span(format!("path '{}' is not valid UTF-8", input_path.display())))?;
        let resolved = resolve_input_path(input)?;
        let source_edition = crate::source_edition(&resolved)?;
        if source_edition != crate::CellScriptEdition::Edition2026 {
            return Err(CompileError::without_span(format!(
                "source migration requires an Edition 2026 input, found Edition {}",
                source_edition.as_str()
            )));
        }
        let source = std::fs::read_to_string(&resolved)
            .map_err(|error| CompileError::without_span(format!("failed to read migration input '{}': {error}", resolved)))?;
        let candidate = crate::frontend::migrate_source_to_2027(&source)?;
        let legacy = crate::compile(
            &source,
            CompileOptions {
                edition: crate::CellScriptEdition::Edition2026,
                target: Some("riscv64-elf".to_string()),
                ..CompileOptions::default()
            },
        )?;
        let migrated = crate::compile(
            &candidate.source,
            CompileOptions {
                edition: crate::CellScriptEdition::Edition2027,
                target: Some("riscv64-elf".to_string()),
                ..CompileOptions::default()
            },
        )?;
        let legacy_ids = &legacy.metadata.typed_semantics.foundation.identities;
        let migrated_ids = &migrated.metadata.typed_semantics.foundation.identities;
        if legacy_ids.core_semantic_id != migrated_ids.core_semantic_id {
            return Err(CompileError::without_span("migration candidate changed CoreSemanticId; no candidate was emitted"));
        }
        if legacy.artifact_bytes != migrated.artifact_bytes {
            return Err(CompileError::without_span(
                "migration candidate changed generated RISC-V ELF bytes; no candidate was emitted",
            ));
        }

        let rendered = if args.json {
            serde_json::to_string_pretty(&serde_json::json!({
                "schema": candidate.schema,
                "source_edition": candidate.source_edition,
                "target_edition": candidate.target_edition,
                "kind": candidate.kind,
                "core_semantic_id": migrated_ids.core_semantic_id,
                "source_entry_contract_id": legacy_ids.entry_contract_id,
                "target_entry_contract_id": migrated_ids.entry_contract_id,
                "artifact_byte_identical": true,
                "source": candidate.source,
            }))
            .map_err(|error| CompileError::without_span(format!("failed to serialize migration report: {error}")))?
        } else {
            candidate.source
        };
        if let Some(output_path) = args.output.as_ref() {
            if let Some(parent) = output_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(output_path, rendered)?;
            if !args.json {
                println!("{}", "Edition 2027 migration candidate generated".green());
                println!("  Output: {}", output_path.display());
                println!("  Evidence: CoreSemanticId matched; RISC-V ELF byte-identical");
            }
        } else {
            print!("{}", rendered);
            if !rendered.ends_with('\n') {
                println!();
            }
        }
        Ok(())
    }

    fn interface(args: InterfaceArgs) -> Result<()> {
        let input_path = args.input.unwrap_or_else(|| PathBuf::from("."));
        let input = Utf8Path::from_path(&input_path)
            .ok_or_else(|| crate::error::CompileError::without_span(format!("path '{}' is not valid UTF-8", input_path.display())))?;
        let result = compile_path(
            input,
            CompileOptions {
                edition: crate::CURRENT_EDITION,
                opt_level: 0,
                output: None,
                debug: false,
                target: args.target,
                target_profile: args.target_profile,
                primitive_compat: None,
            },
        )?;
        let value = serde_json::json!({
            "interface_hash": result.metadata.interface_hash,
            "interface": result.metadata.public_interface,
        });
        let json = serde_json::to_string_pretty(&value)
            .map_err(|error| crate::error::CompileError::without_span(format!("failed to serialize public interface: {error}")))?;
        if let Some(output_path) = args.output.as_ref() {
            if let Some(parent) = output_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(output_path, format!("{json}\n"))?;
            println!("{}", "Public interface generated".green());
            println!("  Hash: {}", result.metadata.interface_hash);
            println!("  Output: {}", output_path.display());
        } else {
            println!("{json}");
        }
        Ok(())
    }

    fn interface_diff(args: InterfaceDiffArgs) -> Result<()> {
        let old = read_or_compile_interface(&args.old)?;
        let new = read_or_compile_interface(&args.new)?;
        let report = crate::interface::compare(&old, &new);
        let json = serde_json::to_string_pretty(&report)
            .map_err(|error| crate::error::CompileError::without_span(format!("failed to serialize interface report: {error}")))?;
        if let Some(output_path) = args.output.as_ref() {
            if let Some(parent) = output_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(output_path, format!("{json}\n"))?;
        }
        if args.json || args.output.is_none() {
            println!("{json}");
        } else {
            println!("Interface compatibility: {}", if report.compatible { "compatible" } else { "breaking" });
            for dimension in &report.dimensions {
                println!("  {}: {}", dimension.dimension, dimension.classification);
            }
            if let Some(output_path) = args.output.as_ref() {
                println!("  Output: {}", output_path.display());
            }
        }
        if !report.compatible {
            return Err(crate::error::CompileError::without_span("public interface contains breaking changes").with_code("E2501"));
        }
        Ok(())
    }

    fn constraints(args: ConstraintsArgs) -> Result<()> {
        if args.entry_action.is_some() && args.entry_lock.is_some() {
            return Err(crate::error::CompileError::without_span(
                "constraints accepts either --entry-action or --entry-lock, not both",
            ));
        }
        let input_path = args.input.unwrap_or_else(|| PathBuf::from("."));
        let input = Utf8Path::from_path(&input_path)
            .ok_or_else(|| crate::error::CompileError::without_span(format!("path '{}' is not valid UTF-8", input_path.display())))?;
        let options = CompileOptions {
            edition: crate::CURRENT_EDITION,
            opt_level: 0,
            output: None,
            debug: false,
            target: args.target,
            target_profile: args.target_profile,
            primitive_compat: None,
        };
        let result = match (args.entry_action.as_deref(), args.entry_lock.as_deref()) {
            (Some(action), None) => compile_path_with_entry_action(input, options, action),
            (None, Some(lock)) => compile_path_with_entry_lock(input, options, lock),
            (None, None) => compile_path(input, options),
            (Some(_), Some(_)) => unreachable!("validated above"),
        }?;
        let json = serde_json::to_string_pretty(&result.metadata.constraints)
            .map_err(|error| crate::error::CompileError::without_span(format!("failed to serialize constraints: {}", error)))?;

        if let Some(output_path) = args.output {
            if let Some(parent) = output_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&output_path, json)?;
            println!("{}", "Constraints generated".green());
            println!("  Output: {}", output_path.display());
        } else {
            println!("{}", json);
        }
        Ok(())
    }

    fn abi(args: AbiArgs) -> Result<()> {
        if args.action.is_some() && args.lock.is_some() {
            return Err(crate::error::CompileError::without_span("abi accepts either --action or --lock, not both"));
        }

        let input_path = args.input.unwrap_or_else(|| PathBuf::from("."));
        let input = Utf8Path::from_path(&input_path)
            .ok_or_else(|| crate::error::CompileError::without_span(format!("path '{}' is not valid UTF-8", input_path.display())))?;
        let result = compile_path(
            input,
            CompileOptions {
                edition: crate::CURRENT_EDITION,
                opt_level: 0,
                output: None,
                debug: false,
                target: args.target,
                target_profile: args.target_profile,
                primitive_compat: None,
            },
        )?;
        let selected = select_entry_witness_metadata(&result.metadata, args.action.as_deref(), args.lock.as_deref())?;
        let entry_constraints = result
            .metadata
            .constraints
            .entry_abi
            .iter()
            .find(|entry| entry.entry_kind == selected.kind && entry.entry_name == selected.name)
            .ok_or_else(|| {
                crate::error::CompileError::without_span(format!(
                    "entry ABI constraints for {} '{}' were not found in metadata",
                    selected.kind, selected.name
                ))
            })?;

        let params = selected
            .params
            .iter()
            .map(|param| {
                let runtime_bound = selected.runtime_bound_param_names.contains(&param.name) || param.lock_args_data_source;
                let payload_bound =
                    !param.lock_args_data_source && !param.cell_bound_abi && !param.ty.starts_with('&') && !runtime_bound;
                let layout = entry_constraints.params.iter().find(|candidate| candidate.name == param.name);
                serde_json::json!({
                    "name": param.name,
                    "type": param.ty,
                    "payload_bound": payload_bound,
                    "runtime_bound": runtime_bound,
                    "cell_bound": param.cell_bound_abi,
                    "schema_pointer_abi": param.schema_pointer_abi,
                    "fixed_byte_len": param.fixed_byte_len,
                    "abi_kind": layout.map(|layout| layout.abi_kind.as_str()),
                    "abi_slots": layout.map(|layout| layout.abi_slots),
                    "slot_start": layout.map(|layout| layout.slot_start),
                    "slot_end": layout.map(|layout| layout.slot_end),
                    "witness_bytes": layout.map(|layout| layout.witness_bytes),
                    "stack_spill_bytes": layout.map(|layout| layout.stack_spill_bytes),
                    "supported": layout.map(|layout| layout.supported).unwrap_or(false),
                    "unsupported_reason": layout.and_then(|layout| layout.unsupported_reason.as_deref()),
                })
            })
            .collect::<Vec<_>>();
        let payload_params = selected
            .params
            .iter()
            .filter(|param| {
                !param.lock_args_data_source
                    && !param.cell_bound_abi
                    && !param.ty.starts_with('&')
                    && !selected.runtime_bound_param_names.contains(&param.name)
            })
            .map(|param| param.name.as_str())
            .collect::<Vec<_>>();
        let runtime_bound_params = selected
            .runtime_bound_param_names
            .iter()
            .map(|name| name.as_str())
            .chain(selected.params.iter().filter(|param| param.lock_args_data_source).map(|param| param.name.as_str()))
            .collect::<Vec<_>>();
        let summary = serde_json::json!({
            "status": if entry_constraints.unsupported { "fail" } else { "ok" },
            "abi": ENTRY_WITNESS_ABI,
            "placement_abi": ENTRY_WITNESS_PLACEMENT_ABI,
            "witness_args_field": ENTRY_WITNESS_PLACEMENT_FIELD,
            "witness_source": ENTRY_WITNESS_PLACEMENT_SOURCE,
            "raw_v1_compatible": false,
            "target_profile": result.metadata.target_profile.name,
            "entry_kind": selected.kind,
            "entry": selected.name,
            "payload_params": payload_params,
            "runtime_bound_params": runtime_bound_params,
            "layout": entry_constraints,
            "params": params,
        });
        let json = serde_json::to_string_pretty(&summary)
            .map_err(|error| crate::error::CompileError::without_span(format!("failed to serialize ABI report: {}", error)))?;

        if let Some(output_path) = args.output {
            if let Some(parent) = output_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&output_path, json)?;
            println!("{}", "ABI report generated".green());
            println!("  Output: {}", output_path.display());
        } else {
            println!("{}", json);
        }
        Ok(())
    }

    fn scheduler_plan(args: SchedulerPlanArgs) -> Result<()> {
        let input_path = args.input.unwrap_or_else(|| PathBuf::from("."));
        let input = Utf8Path::from_path(&input_path)
            .ok_or_else(|| crate::error::CompileError::without_span(format!("path '{}' is not valid UTF-8", input_path.display())))?;
        let result = compile_path(
            input,
            CompileOptions {
                edition: crate::CURRENT_EDITION,
                opt_level: 0,
                output: None,
                debug: false,
                target: args.target,
                target_profile: args.target_profile,
                primitive_compat: None,
            },
        )?;

        let actions = result
            .metadata
            .actions
            .iter()
            .map(|action| {
                let mut reasons = Vec::new();
                if !action.parallelizable {
                    reasons.push("parallelizable=false".to_string());
                }
                if !action.touches_shared.is_empty() {
                    reasons.push("touches-shared-state".to_string());
                }
                serde_json::json!({
                    "action": action.name,
                    "effect_class": action.effect_class,
                    "parallelizable": action.parallelizable,
                    "touches_shared": action.touches_shared,
                    "estimated_cycles": action.estimated_cycles,
                    "scheduler_witness_abi": action.scheduler_witness_abi,
                    "admission": if action.parallelizable && action.touches_shared.is_empty() {
                        "parallel-candidate"
                    } else {
                        "serial-required"
                    },
                    "reasons": reasons,
                })
            })
            .collect::<Vec<_>>();

        let mut conflicts = Vec::new();
        for (left_index, left) in result.metadata.actions.iter().enumerate() {
            for right in result.metadata.actions.iter().skip(left_index + 1) {
                let shared =
                    left.touches_shared.iter().filter(|touch| right.touches_shared.contains(*touch)).cloned().collect::<Vec<_>>();
                if !shared.is_empty() {
                    conflicts.push(serde_json::json!({
                        "left": left.name,
                        "right": right.name,
                        "shared_touches": shared,
                        "policy": "must-not-run-in-parallel",
                    }));
                }
            }
        }

        let total_estimated_cycles = result.metadata.actions.iter().map(|action| action.estimated_cycles).sum::<u64>();
        let max_estimated_cycles = result.metadata.actions.iter().map(|action| action.estimated_cycles).max().unwrap_or_default();
        let serial_required_actions = result
            .metadata
            .actions
            .iter()
            .filter(|action| !action.parallelizable || !action.touches_shared.is_empty())
            .map(|action| action.name.as_str())
            .collect::<Vec<_>>();
        let summary = serde_json::json!({
            "status": "ok",
            "target_profile": result.metadata.target_profile.name,
            "policy": "cellscript-scheduler-hints-v1",
            "action_count": result.metadata.actions.len(),
            "serial_required_actions": serial_required_actions,
            "conflict_count": conflicts.len(),
            "conflicts": conflicts,
            "estimated_cycles": {
                "total": total_estimated_cycles,
                "max_action": max_estimated_cycles,
            },
            "actions": actions,
        });
        let json = serde_json::to_string_pretty(&summary)
            .map_err(|error| crate::error::CompileError::without_span(format!("failed to serialize scheduler plan: {}", error)))?;

        if let Some(output_path) = args.output {
            if let Some(parent) = output_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&output_path, json)?;
            println!("{}", "Scheduler plan generated".green());
            println!("  Output: {}", output_path.display());
        } else {
            println!("{}", json);
        }
        Ok(())
    }

    fn ckb_hash(args: CkbHashArgs) -> Result<()> {
        let source_count = usize::from(args.input.is_some()) + usize::from(args.hex.is_some()) + usize::from(args.file.is_some());
        if source_count > 1 {
            return Err(crate::error::CompileError::without_span(
                "ckb-hash accepts at most one input source: positional UTF-8 text, --hex, or --file",
            ));
        }
        let bytes = if let Some(hex) = args.hex.as_deref() {
            decode_hex_arg("ckb-hash", hex, None)?
        } else if let Some(path) = args.file.as_ref() {
            std::fs::read(path).map_err(|error| {
                crate::error::CompileError::without_span(format!("failed to read CKB hash input '{}': {}", path.display(), error))
            })?
        } else {
            args.input.unwrap_or_default().into_bytes()
        };
        let hash = crate::ckb_blake2b256(&bytes);
        let hash_hex = crate::hex_encode(&hash);
        CommandOutcome {
            machine: serde_json::json!({
                "status": "ok",
                "algorithm": "blake2b-256",
                "personalization": std::str::from_utf8(crate::CKB_DEFAULT_HASH_PERSONALIZATION).unwrap_or("ckb-default-hash"),
                "input_bytes": bytes.len(),
                "hash": hash_hex,
            }),
            human_lines: vec![hash_hex],
        }
        .emit(args.json)
    }

    fn ckb_std_compat(args: CkbStdCompatArgs) -> Result<()> {
        let report = serde_json::json!({
            "status": "ok",
            "schema": "cellscript-ckb-std-compat-report-v0.19",
            "runtime_policy": "inline",
            "compiler_core_dependency": "no-ckb-std",
            "compatibility_dependency_scope": "dev-test-and-adapter-contract",
            "abi_source": "src/ckb_abi.rs",
            "test_evidence": {
                "compat_tests": "tests/ckb_std_compat.rs",
                "constant_parity": true,
                "source_view_decoding": true,
                "witness_args_layout": true,
                "type_id_contract": true,
                "since_epoch_contract": true,
                "occupied_capacity_field": true,
                "packed_transaction_materialization": true,
                "script_construction_api": true,
            },
            "ckb_std_refs": {
                "constants": "ckb_std::ckb_constants",
                "witness_args": "ckb_types::packed::WitnessArgs",
                "type_id": "ckb_std::type_id",
                "since": "ckb_std::since",
                "occupied_capacity": "ckb_std::high_level::load_cell_occupied_capacity",
            },
            "inline_abi": {
                "syscalls": {
                    "load_cell_by_field": crate::ckb_abi::syscall::LOAD_CELL_BY_FIELD,
                    "load_witness": crate::ckb_abi::syscall::LOAD_WITNESS,
                    "load_input_by_field": crate::ckb_abi::syscall::LOAD_INPUT_BY_FIELD,
                    "spawn": crate::ckb_abi::syscall::SPAWN,
                },
                "sources": {
                    "input": crate::ckb_abi::source::INPUT,
                    "output": crate::ckb_abi::source::OUTPUT,
                    "group_input": crate::ckb_abi::source::GROUP_INPUT,
                    "group_output": crate::ckb_abi::source::GROUP_OUTPUT,
                },
                "fields": {
                    "cell_occupied_capacity": crate::ckb_abi::cell_field::OCCUPIED_CAPACITY,
                    "input_since": crate::ckb_abi::input_field::SINCE,
                },
            },
            "adapter_boundary": {
                "transaction_realizer": "ckb-sdk-rust-or-CCC-adapter",
                "compiler_core_uses_ckb_sdk_rust": false,
                "action_build_contract": "cellscript-ckb-adapter-contract-v0.19",
                "requires_node_acceptance_for_production": true,
                "script_construction": {
                    "owner": "adapter",
                    "packed_type": "ckb_types::packed::Script",
                    "evidence_schema": "cellscript-ckb-script-evidence-v0.19",
                    "supports": [
                        "arbitrary_code_hash",
                        "hash_type",
                        "args",
                        "script_hash",
                        "script_ref_readback",
                        "explicit_cell_dep_binding",
                        "args_exact_prefix_suffix",
                        "owner_mode_args"
                    ],
                },
            },
            "witness_args_policy": {
                "entry_payload_abi": ENTRY_WITNESS_ABI,
                "placement_abi": ENTRY_WITNESS_PLACEMENT_ABI,
                "entry_payload_owner": "compiler",
                "final_witness_args_owner": "adapter",
                "default_action_payload_field": ENTRY_WITNESS_PLACEMENT_FIELD,
                "runtime_source": ENTRY_WITNESS_PLACEMENT_SOURCE,
                "raw_v1_compatible": false,
                "lock_signature_policy": "explicit-adapter-owned-do-not-overwrite",
                "placement_requires_deployment_role": true,
                "ckb_reference": "ckb_types::packed::WitnessArgs",
            },
            "non_goals": [
                "does-not-execute-ckb-vm",
                "does-not-query-live-cells",
                "does-not-resolve-celldeps",
                "does-not-sign-or-submit"
            ],
        });

        CommandOutcome {
            human_lines: vec![
                format!("CKB std compatibility: {}", report["status"].as_str().unwrap_or("unknown")),
                format!("  Schema: {}", report["schema"].as_str().unwrap_or("unknown")),
                format!("  Runtime policy: {}", report["runtime_policy"].as_str().unwrap_or("unknown")),
                format!("  ABI source: {}", report["abi_source"].as_str().unwrap_or("unknown")),
                format!("  Test evidence: {}", report["test_evidence"]["compat_tests"].as_str().unwrap_or("unknown")),
            ],
            machine: report,
        }
        .emit(args.json)
    }

    fn explain(args: ExplainArgs) -> Result<()> {
        if let Some(info) = crate::error::compiler_error_info_by_code(&args.code.to_ascii_uppercase()) {
            let outcome = CommandOutcome {
                machine: serde_json::json!({
                    "status": "ok",
                    "domain": "compiler",
                    "code": info.code,
                    "name": info.name,
                    "description": info.description,
                    "hint": info.hint,
                }),
                human_lines: vec![
                    format!("CellScript compiler error {}: {}", info.code, info.name),
                    format!("  Description: {}", info.description),
                    format!("  Hint: {}", info.hint),
                ],
            };
            return outcome.emit(args.json);
        }

        let info = runtime_error_info_from_query(&args.code).ok_or_else(|| {
            crate::error::CompileError::without_span(format!(
                "unknown CellScript error '{}'; use a runtime numeric/E-code/name or compiler E2xxx code",
                args.code
            ))
        })?;

        CommandOutcome {
            machine: serde_json::json!({
                "status": "ok",
                "code": info.code,
                "ecode": format!("E{:04}", info.code),
                "name": info.name,
                "description": info.description,
                "hint": info.hint,
            }),
            human_lines: vec![
                format!("CellScript runtime error E{:04} ({}): {}", info.code, info.code, info.name),
                format!("  Description: {}", info.description),
                format!("  Hint: {}", info.hint),
            ],
        }
        .emit(args.json)
    }

    fn explain_proof(args: ExplainProofArgs) -> Result<()> {
        let input_path = args.input.unwrap_or_else(|| PathBuf::from("."));
        let input = Utf8Path::from_path(&input_path)
            .ok_or_else(|| crate::error::CompileError::without_span(format!("path '{}' is not valid UTF-8", input_path.display())))?;
        let result = compile_path(
            input,
            CompileOptions {
                edition: crate::CURRENT_EDITION,
                opt_level: 0,
                output: None,
                debug: false,
                target: args.target,
                target_profile: args.target_profile,
                primitive_compat: None,
            },
        )?;
        let proof_plan = result.metadata.runtime.proof_plan;

        if args.json {
            let proof_plan_summary = proof_plan_summary_json(&proof_plan);
            let summary = serde_json::json!({
                "status": "ok",
                "module": result.metadata.module,
                "target_profile": result.metadata.target_profile.name,
                "proof_plan_summary": proof_plan_summary,
                "proof_plan": proof_plan,
            });
            let json = serde_json::to_string_pretty(&summary)
                .map_err(|error| crate::error::CompileError::without_span(format!("failed to serialize ProofPlan: {}", error)))?;
            println!("{}", json);
            return Ok(());
        }

        println!("Covenant ProofPlan for module `{}`", result.metadata.module);
        print_proof_plan_summary(&proof_plan);
        if proof_plan.is_empty() {
            println!("  No ProofPlan records emitted.");
            return Ok(());
        }
        for plan in &proof_plan {
            print_proof_plan_record(plan);
        }
        Ok(())
    }

    fn explain_assumptions(args: ExplainAssumptionsArgs) -> Result<()> {
        let result = compile_cli_input(
            args.input.as_ref(),
            CompileOptions {
                edition: crate::CURRENT_EDITION,
                opt_level: 0,
                output: None,
                debug: false,
                target: args.target,
                target_profile: args.target_profile,
                primitive_compat: None,
            },
        )?;
        let assumptions = result.metadata.runtime.builder_assumptions.clone();
        let summary = serde_json::json!({
            "status": "ok",
            "module": result.metadata.module,
            "target_profile": result.metadata.target_profile.name,
            "assumption_count": assumptions.len(),
            "proof_plan_soundness": result.metadata.runtime.proof_plan_soundness,
            "builder_assumptions": assumptions,
        });
        let mut human_lines = vec![
            format!("Builder assumptions for module `{}`", result.metadata.module),
            format!("  Assumptions: {}", summary["assumption_count"]),
            format!("  ProofPlan soundness: {}", summary["proof_plan_soundness"]["status"].as_str().unwrap_or("unknown")),
        ];
        human_lines.extend(
            result
                .metadata
                .runtime
                .builder_assumptions
                .iter()
                .map(|assumption| format!("  - {} [{}] {}", assumption.assumption_id, assumption.kind, assumption.feature)),
        );
        CommandOutcome { machine: summary, human_lines }.emit(args.json)
    }

    fn validate_tx(args: ValidateTxArgs) -> Result<()> {
        let metadata = read_metadata_json(&args.against)?;
        let tx = read_json_value(&args.tx)?;
        let report = crate::assumptions::validate_transaction_against_metadata(&metadata, &tx);
        let summary = serde_json::json!({
            "status": report.status,
            "validation_level": "cellscript-metadata-evidence",
            "ckb_vm_execution": false,
            "tx_pool_acceptance": false,
            "metadata": args.against.display().to_string(),
            "tx": args.tx.display().to_string(),
            "validation": report,
        });
        let failed = summary["status"] == "failed";
        let outcome = CommandOutcome { machine: summary, human_lines: vec![format!("Transaction validation: {}", report.status)] };
        if failed {
            return Err(outcome.failure("transaction violates builder assumptions"));
        }
        outcome.emit(args.json)
    }

    fn solve_tx(args: SolveTxArgs) -> Result<()> {
        let result = compile_cli_input(
            args.input.as_ref(),
            CompileOptions {
                edition: crate::CURRENT_EDITION,
                opt_level: 0,
                output: None,
                debug: false,
                target: args.target,
                target_profile: args.target_profile,
                primitive_compat: None,
            },
        )?;
        let template = transaction_solver_template(&result.metadata);
        write_or_print_json(args.output.as_ref(), &template, args.json, "Transaction template generated (tx solve is not a solver)")?;
        Ok(())
    }

    fn verify_ckb_fixtures(args: VerifyCkbFixturesArgs) -> Result<()> {
        let manifest_bytes = std::fs::read(&args.manifest).map_err(|error| {
            crate::error::CompileError::without_span(format!(
                "failed to read fixture manifest '{}': {}",
                args.manifest.display(),
                error
            ))
        })?;
        let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes).map_err(|error| {
            crate::error::CompileError::without_span(format!(
                "failed to parse fixture manifest '{}': {}",
                args.manifest.display(),
                error
            ))
        })?;
        let base_dir = args.manifest.parent().unwrap_or_else(|| Path::new("."));
        let report = ckb_fixture_manifest_report(&manifest, base_dir, &manifest_bytes);
        let issue_count = report["issue_count"].as_u64().unwrap_or(0);
        let mut human_lines = vec![
            format!("CKB fixture manifest verification: {}", report["status"].as_str().unwrap_or("unknown")),
            format!("  Manifest schema: {}", report["manifest_schema"].as_str().unwrap_or("unknown")),
            format!("  Execution level: {}", report["execution_level"].as_str().unwrap_or("unknown")),
            format!("  Suites: {}", report["suite_count"].as_u64().unwrap_or(0)),
            format!("  Fixtures: {}", report["fixture_count"].as_u64().unwrap_or(0)),
            format!("  Issues: {issue_count}"),
        ];
        if let Some(issues) = report["issues"].as_array() {
            human_lines.extend(issues.iter().map(|issue| format!("  - {}", issue.as_str().unwrap_or("<invalid issue>"))));
        }
        let outcome = CommandOutcome { machine: report, human_lines };
        if issue_count == 0 {
            outcome.emit(args.json)
        } else {
            Err(outcome.failure(format!("CKB fixture manifest failed verification: {issue_count} issue(s)")))
        }
    }

    fn deploy_plan(args: DeployPlanArgs) -> Result<()> {
        let result = compile_cli_input(
            args.input.as_ref(),
            CompileOptions {
                edition: crate::CURRENT_EDITION,
                opt_level: 0,
                output: None,
                debug: false,
                target: args.target,
                target_profile: args.target_profile,
                primitive_compat: None,
            },
        )?;
        let plan = deployment_plan_json(&result.metadata);
        write_or_print_json(args.output.as_ref(), &plan, args.json, "Deployment plan generated")?;
        Ok(())
    }

    fn verify_deploy(args: VerifyDeployArgs) -> Result<()> {
        let plan = read_json_value(&args.plan)?;
        let violations = verify_deploy_plan_json(&plan);
        let summary = serde_json::json!({
            "status": if violations.is_empty() { "ok" } else { "failed" },
            "plan": args.plan.display().to_string(),
            "violations": violations,
        });
        let failed = summary["status"] == "failed";
        let outcome = CommandOutcome {
            human_lines: vec![format!("Deploy plan verification: {}", summary["status"].as_str().unwrap_or("unknown"))],
            machine: summary,
        };
        if failed {
            return Err(outcome.failure("deploy plan verification failed"));
        }
        outcome.emit(args.json)
    }

    fn diff_deploy(args: DiffDeployArgs) -> Result<()> {
        let old = read_json_value(&args.old)?;
        let new = read_json_value(&args.new)?;
        let diff = json_diff_report("deploy", &old, &new);
        print_or_text_json(args.json, &diff, "Deploy diff")?;
        Ok(())
    }

    fn lock_deps(args: LockDepsArgs) -> Result<()> {
        let result = compile_cli_input(
            args.input.as_ref(),
            CompileOptions {
                edition: crate::CURRENT_EDITION,
                opt_level: 0,
                output: None,
                debug: false,
                target: args.target,
                target_profile: args.target_profile,
                primitive_compat: None,
            },
        )?;
        let lock = dependency_lock_json(&result.metadata);
        write_or_print_json(args.output.as_ref(), &lock, args.json, "Dependency lock generated")?;
        Ok(())
    }

    fn proof_diff(args: ProofDiffArgs) -> Result<()> {
        let old = read_metadata_json(&args.old)?;
        let new = read_metadata_json(&args.new)?;
        let diff = proof_diff_report(&old, &new);
        print_or_text_json(args.json, &diff, "Proof diff")?;
        Ok(())
    }

    fn profile(args: ProfileArgs) -> Result<()> {
        let result = compile_cli_input(
            args.input.as_ref(),
            CompileOptions {
                edition: crate::CURRENT_EDITION,
                opt_level: 0,
                output: None,
                debug: false,
                target: args.target,
                target_profile: args.target_profile,
                primitive_compat: None,
            },
        )?;
        let report = profile_report_json(&result.metadata, args.entry.as_deref());
        print_or_text_json(args.json, &report, "Profile")?;
        Ok(())
    }

    fn trace_tx(args: TraceTxArgs) -> Result<()> {
        let metadata = read_metadata_json(&args.against)?;
        let tx = read_json_value(&args.tx)?;
        let validation = crate::assumptions::validate_transaction_against_metadata(&metadata, &tx);
        let trace = trace_tx_report_json(&metadata, &validation);
        let outcome = CommandOutcome {
            human_lines: vec![format!("Transaction trace: {}", trace["status"].as_str().unwrap_or("unknown"))],
            machine: trace,
        };
        if validation.status == "failed" {
            return Err(outcome.failure("transaction trace found builder assumption violations"));
        }
        outcome.emit(args.json)
    }

    fn audit_bundle(args: AuditBundleArgs) -> Result<()> {
        let result = compile_cli_input(
            args.input.as_ref(),
            CompileOptions {
                edition: crate::CURRENT_EDITION,
                opt_level: 0,
                output: None,
                debug: false,
                target: args.target,
                target_profile: args.target_profile,
                primitive_compat: None,
            },
        )?;
        let output = args.output.unwrap_or_else(|| PathBuf::from("target/cellscript-audit-bundle"));
        std::fs::create_dir_all(&output)?;
        let bundle = audit_bundle_json(&result.metadata);
        let json_path = output.join("audit-bundle.json");
        let html_path = output.join("index.html");
        std::fs::write(
            &json_path,
            serde_json::to_string_pretty(&bundle)
                .map_err(|error| crate::error::CompileError::without_span(format!("failed to serialize audit bundle: {}", error)))?,
        )?;
        std::fs::write(&html_path, audit_bundle_html(&bundle))?;
        let summary = serde_json::json!({
            "status": "ok",
            "output": output.display().to_string(),
            "json": json_path.display().to_string(),
            "html": html_path.display().to_string(),
        });
        CommandOutcome {
            machine: summary,
            human_lines: vec![
                "Audit bundle generated".to_string(),
                format!("  JSON: {}", json_path.display()),
                format!("  HTML: {}", html_path.display()),
            ],
        }
        .emit(args.json)
    }

    fn explain_generics(args: ExplainGenericsArgs) -> Result<()> {
        let input_path = args.input.unwrap_or_else(|| PathBuf::from("."));
        let input = Utf8Path::from_path(&input_path)
            .ok_or_else(|| crate::error::CompileError::without_span(format!("path '{}' is not valid UTF-8", input_path.display())))?;
        let result = compile_path(
            input,
            CompileOptions {
                edition: crate::CURRENT_EDITION,
                opt_level: 0,
                output: None,
                debug: false,
                target: args.target,
                target_profile: args.target_profile,
                primitive_compat: None,
            },
        )?;
        let value_instantiations = result.metadata.generic_instantiations;
        let collection_instantiations = result.metadata.runtime.collection_instantiations;

        let mut human_lines = Vec::new();
        if value_instantiations.is_empty() {
            human_lines.push("No value-generic monomorphizations found.".to_string());
        } else {
            human_lines.push("Checked value-generic monomorphizations:".to_string());
            for instantiation in &value_instantiations {
                human_lines.push(format!("  {} {} -> {}", instantiation.kind, instantiation.identity, instantiation.concrete_name));
                human_lines.push(format!("    type arguments: {}", instantiation.type_arguments.join(", ")));
                human_lines.push(format!("    value abilities: passed (registry v{})", instantiation.value_ability_registry_version));
                human_lines.push(format!(
                    "    layout policy: {}",
                    if instantiation.fixed_layout_required {
                        "fixed value layout required"
                    } else {
                        "callable specialization; no container layout"
                    }
                ));
                human_lines.push(format!(
                    "    Cell argument policy: {}",
                    if instantiation.cell_backed_layout_rejected {
                        "passed; hidden Cell-backed values are forbidden in this layout"
                    } else {
                        "passed; Cell-backed arguments require an explicit cell constraint"
                    }
                ));
            }
        }
        if collection_instantiations.is_empty() {
            human_lines.push("No checked bounded generic collection instantiations found.".to_string());
        } else {
            human_lines.push("Checked bounded generic collection instantiations:".to_string());
            for instantiation in &collection_instantiations {
                human_lines.push(format!(
                    "  {} {}: {} -> {} ({} byte element, max {}, {})",
                    instantiation.scope_kind,
                    instantiation.scope_name,
                    instantiation.collection_ty,
                    instantiation.element_ty,
                    instantiation.element_width_bytes,
                    instantiation.max_elements,
                    instantiation.status
                ));
                human_lines.push(format!("    backing: {}", instantiation.backing));
                human_lines.push(format!("    helpers: {}", instantiation.helpers.join(", ")));
            }
        }
        let value_instantiation_view = value_instantiations
            .iter()
            .map(|instantiation| {
                serde_json::json!({
                    "kind": instantiation.kind,
                    "module": instantiation.module,
                    "template": instantiation.template,
                    "concrete_name": instantiation.concrete_name,
                    "identity": instantiation.identity,
                    "type_arguments": instantiation.type_arguments,
                    "verification": {
                        "value_abilities": "passed",
                        "value_ability_registry_version": instantiation.value_ability_registry_version,
                        "layout_policy": if instantiation.fixed_layout_required {
                            "fixed-value-layout-required"
                        } else {
                            "callable-specialization-no-container-layout"
                        },
                        "cell_argument_policy": if instantiation.cell_backed_layout_rejected {
                            "passed-hidden-cell-values-forbidden"
                        } else {
                            "passed-explicit-cell-constraint-required"
                        },
                        "phantom_arguments_in_identity": instantiation.identity_includes_phantom_arguments,
                    },
                })
            })
            .collect::<Vec<_>>();
        CommandOutcome {
            machine: serde_json::json!({
                "status": "ok",
                "count": value_instantiations.len() + collection_instantiations.len(),
                "value_instantiations": value_instantiation_view,
                "collection_instantiations": collection_instantiations,
            }),
            human_lines,
        }
        .emit(args.json)
    }

    fn explain_graph(args: ExplainGraphArgs) -> Result<()> {
        let input_path = args.input.unwrap_or_else(|| PathBuf::from("."));
        let input = Utf8Path::from_path(&input_path)
            .ok_or_else(|| crate::error::CompileError::without_span(format!("path '{}' is not valid UTF-8", input_path.display())))?;
        let result = compile_path(
            input,
            CompileOptions {
                edition: crate::CURRENT_EDITION,
                opt_level: 0,
                output: None,
                debug: false,
                target: args.target,
                target_profile: args.target_profile,
                primitive_compat: None,
            },
        )?;
        let graph = protocol_graph_json(&result.metadata);
        let format = args.format.as_deref().unwrap_or(if args.json { "json" } else { "summary" });
        match format {
            "json" => print_json(&graph),
            "mermaid" => {
                print!("{}", protocol_graph_mermaid(&graph));
                Ok(())
            }
            "summary" => {
                println!("ProtocolGraph: {}", graph["schema"].as_str().unwrap_or("unknown"));
                println!("  Vertices: {}", graph["vertex_count"].as_u64().unwrap_or_default());
                println!("  Edges: {}", graph["edge_count"].as_u64().unwrap_or_default());
                println!("  Cycles: {}", if graph["cycle_detected"].as_bool().unwrap_or(false) { "detected" } else { "not detected" });
                println!("  Role lints: {}", graph["role_warning_count"].as_u64().unwrap_or_default());
                println!("  Role authority: metadata-only (never authorization proof)");
                println!("  Consensus checked: no");
                Ok(())
            }
            other => Err(crate::error::CompileError::without_span(format!(
                "unsupported graph format '{}'; expected json or mermaid",
                other
            ))),
        }
    }

    fn opt_report(args: OptReportArgs) -> Result<()> {
        let input_path = args.input.unwrap_or_else(|| PathBuf::from("."));
        let input = Utf8Path::from_path(&input_path)
            .ok_or_else(|| crate::error::CompileError::without_span(format!("path '{}' is not valid UTF-8", input_path.display())))?;
        let mut rows = Vec::new();
        for opt_level in 0..=3u8 {
            let result = compile_path(
                input,
                CompileOptions {
                    edition: crate::CURRENT_EDITION,
                    opt_level,
                    output: None,
                    debug: false,
                    target: args.target.clone(),
                    target_profile: args.target_profile.clone(),
                    primitive_compat: None,
                },
            )?;
            let artifact = &result.metadata.constraints.artifact;
            let estimated_cycles_total = result.metadata.actions.iter().map(|action| action.estimated_cycles).sum::<u64>();
            let estimated_cycles_max_action =
                result.metadata.actions.iter().map(|action| action.estimated_cycles).max().unwrap_or_default();
            rows.push(serde_json::json!({
                "opt_level": opt_level,
                "artifact_format": result.metadata.artifact_format,
                "target_profile": result.metadata.target_profile.name,
                "artifact_size_bytes": result.artifact_bytes.len(),
                "estimated_cycles_total": estimated_cycles_total,
                "estimated_cycles_max_action": estimated_cycles_max_action,
                "backend_shape": {
                    "text_bytes": artifact.text_bytes,
                    "rodata_bytes": artifact.rodata_bytes,
                    "executable_text_op_count": artifact.executable_text_op_count,
                    "covered_text_op_count": artifact.covered_text_op_count,
                    "relaxed_branch_count": artifact.relaxed_branch_count,
                    "max_cond_branch_abs_distance": artifact.max_cond_branch_abs_distance,
                    "machine_block_count": artifact.machine_block_count,
                    "max_machine_block_size": artifact.max_machine_block_size,
                    "conditional_branch_block_count": artifact.conditional_branch_block_count,
                    "labeled_machine_block_count": artifact.labeled_machine_block_count,
                    "machine_cfg_edge_count": artifact.machine_cfg_edge_count,
                    "machine_call_edge_count": artifact.machine_call_edge_count,
                    "unreachable_machine_block_count": artifact.unreachable_machine_block_count,
                    "layout_order_block_count": artifact.layout_order_block_count,
                    "layout_order_text_size": artifact.layout_order_text_size,
                },
                "constraints_status": result.metadata.constraints.status,
                "constraints_warnings": result.metadata.constraints.warnings.len(),
                "constraints_failures": result.metadata.constraints.failures.len(),
                "source_content_hash": result.metadata.source_content_hash,
            }));
        }
        let baseline_size = rows.first().and_then(|row| row["artifact_size_bytes"].as_u64()).unwrap_or_default();
        let baseline_text_bytes = rows.first().and_then(|row| row["backend_shape"]["text_bytes"].as_u64());
        let baseline_executable_text_ops = rows.first().and_then(|row| row["backend_shape"]["executable_text_op_count"].as_u64());
        let baseline_estimated_cycles_total = rows.first().and_then(|row| row["estimated_cycles_total"].as_u64()).unwrap_or_default();
        let summary_rows = rows
            .into_iter()
            .map(|mut row| {
                let size = row["artifact_size_bytes"].as_u64().unwrap_or_default();
                row["artifact_size_delta_from_o0"] = serde_json::json!(size as i64 - baseline_size as i64);
                row["text_bytes_delta_from_o0"] = match (row["backend_shape"]["text_bytes"].as_u64(), baseline_text_bytes) {
                    (Some(value), Some(baseline)) => serde_json::json!(value as i64 - baseline as i64),
                    _ => serde_json::Value::Null,
                };
                row["executable_text_op_count_delta_from_o0"] =
                    match (row["backend_shape"]["executable_text_op_count"].as_u64(), baseline_executable_text_ops) {
                        (Some(value), Some(baseline)) => serde_json::json!(value as i64 - baseline as i64),
                        _ => serde_json::Value::Null,
                    };
                let estimated_cycles_total = row["estimated_cycles_total"].as_u64().unwrap_or_default();
                row["estimated_cycles_total_delta_from_o0"] =
                    serde_json::json!(estimated_cycles_total as i64 - baseline_estimated_cycles_total as i64);
                row
            })
            .collect::<Vec<_>>();
        let summary = serde_json::json!({
            "status": "ok",
            "policy": "cellscript-opt-report-v1",
            "input": input_path.display().to_string(),
            "baseline_opt_level": 0,
            "rows": summary_rows,
        });
        let json = serde_json::to_string_pretty(&summary)
            .map_err(|error| crate::error::CompileError::without_span(format!("failed to serialize opt report: {}", error)))?;

        if let Some(output_path) = args.output {
            if let Some(parent) = output_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&output_path, json)?;
            println!("{}", "Optimization report generated".green());
            println!("  Output: {}", output_path.display());
        } else {
            println!("{}", json);
        }
        Ok(())
    }

    fn explain_profile(args: ExplainProfileArgs) -> Result<()> {
        let profile = TargetProfile::from_name(&args.profile)?;
        let metadata = profile.metadata(ArtifactFormat::RiscvElf);
        let summary = serde_json::json!({
            "profile": metadata.name,
            "target_chain": metadata.target_chain,
            "vm_abi": metadata.vm_abi,
            "hash_domain": metadata.hash_domain,
            "syscall_set": metadata.syscall_set,
            "artifact_packaging": metadata.artifact_packaging,
            "header_abi": metadata.header_abi,
            "scheduler_abi": metadata.scheduler_abi,
            "witness_abi": metadata.witness_abi,
            "lock_args_abi": metadata.lock_args_abi,
            "source_encoding": metadata.source_encoding,
            "spawn_ipc_abi": metadata.spawn_ipc_abi,
            "since_abi": metadata.since_abi,
            "cell_dep_abi": metadata.cell_dep_abi,
            "script_ref_abi": metadata.script_ref_abi,
            "output_data_abi": metadata.output_data_abi,
            "capacity_floor_abi": metadata.capacity_floor_abi,
            "type_id_abi": metadata.type_id_abi,
            "tx_version": metadata.tx_version,
            "boundaries": [
                "WitnessArgs fields are explicit CKB witness surfaces, not implicit signer authority",
                "lock_args parameters are typed script args, not implicit signer authority",
                "Source group views are scoped to the active script group",
                "outputs and outputs_data are index-aligned CKB transaction surfaces",
                "capacity floors are declared in shannons and still require builder measurement",
                "script references keep code_hash, hash_type, and args visible",
                "TYPE_ID metadata uses the CKB TYPE_ID ABI and does not hide builder obligations",
                "Spawn/IPC is bounded verifier reuse and does not make type scripts multi-tenant",
                "hash_blake2b(input: Hash) uses CKB Blake2b-256 for one Hash",
                "hash_pair(left: Hash, right: Hash) uses CKB Blake2b-256 over two Hash values; wider byte serialization hashing remains out of scope"
            ],
        });
        if args.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&summary).map_err(|error| {
                    crate::error::CompileError::without_span(format!("failed to serialize profile explanation: {}", error))
                })?
            );
        } else {
            println!("Target profile: {}", summary["profile"].as_str().unwrap_or("unknown"));
            println!("  Target chain: {}", summary["target_chain"].as_str().unwrap_or("unknown"));
            println!("  VM ABI: {}", summary["vm_abi"].as_str().unwrap_or("unknown"));
            println!("  Witness ABI: {}", summary["witness_abi"].as_str().unwrap_or("unknown"));
            println!("  Lock args ABI: {}", summary["lock_args_abi"].as_str().unwrap_or("unknown"));
            println!("  Source encoding: {}", summary["source_encoding"].as_str().unwrap_or("unknown"));
            println!("  Spawn/IPC ABI: {}", summary["spawn_ipc_abi"].as_str().unwrap_or("unknown"));
            println!("  Since ABI: {}", summary["since_abi"].as_str().unwrap_or("unknown"));
            println!("  CellDep ABI: {}", summary["cell_dep_abi"].as_str().unwrap_or("unknown"));
            println!("  Script ref ABI: {}", summary["script_ref_abi"].as_str().unwrap_or("unknown"));
            println!("  Output data ABI: {}", summary["output_data_abi"].as_str().unwrap_or("unknown"));
            println!("  Capacity floor ABI: {}", summary["capacity_floor_abi"].as_str().unwrap_or("unknown"));
            println!("  TYPE_ID ABI: {}", summary["type_id_abi"].as_str().unwrap_or("unknown"));
        }
        Ok(())
    }

    fn action_build(args: ActionBuildArgs) -> Result<()> {
        let input_path = args.input.unwrap_or_else(|| PathBuf::from("."));
        let input = Utf8Path::from_path(&input_path)
            .ok_or_else(|| crate::error::CompileError::without_span(format!("path '{}' is not valid UTF-8", input_path.display())))?;
        let result = compile_path(
            input,
            CompileOptions {
                edition: crate::CURRENT_EDITION,
                opt_level: 1,
                output: None,
                debug: false,
                target: args.target,
                target_profile: args.target_profile.or_else(|| Some("ckb".to_string())),
                primitive_compat: None,
            },
        )?;

        let action = if let Some(name) = args.action.as_deref() {
            result
                .metadata
                .actions
                .iter()
                .find(|action| action.name == name)
                .ok_or_else(|| crate::error::CompileError::without_span(format!("action '{}' was not found in metadata", name)))?
        } else {
            result
                .metadata
                .actions
                .first()
                .ok_or_else(|| crate::error::CompileError::without_span("no actions found in compiled metadata"))?
        };
        let entry_constraints =
            result.metadata.constraints.entry_abi.iter().find(|entry| entry.entry_kind == "action" && entry.entry_name == action.name);

        let ckb = result.metadata.constraints.ckb.as_ref();
        let metadata_bytes = serde_json::to_vec(&result.metadata).map_err(|error| {
            crate::error::CompileError::without_span(format!("failed to serialize metadata for digest: {}", error))
        })?;
        let metadata_hash = crate::hex_encode(&crate::ckb_blake2b256(&metadata_bytes));
        let ckb_contract = ckb.map(|ckb| {
            serde_json::json!({
                "hash_type_policy": ckb.hash_type_policy,
                "capacity_evidence_contract": ckb.capacity_evidence_contract,
                "timelock_policy": ckb.timelock_policy,
                "tx_size_measurement_required": ckb.tx_size_measurement_required,
                "occupied_capacity_measurement_required": ckb.occupied_capacity_measurement_required,
                "dry_run_required_for_production": ckb.dry_run_required_for_production,
            })
        });
        let action_scan_selectors = action_scan_selectors_json(action);
        let transaction_draft = serde_json::json!({
            "format": "cellscript-ccc-transaction-draft-v1",
            "state": "ActionPlan",
            "status": "template",
            "ccc_compatible": true,
            "can_submit": false,
            "ckb_vm_execution": false,
            "tx_pool_acceptance": false,
            "requires_live_cell_resolution": true,
            "requires_packed_materialization": true,
            "packed_materialization": {
                "transaction": "ckb_types::packed::Transaction",
                "cell_output": "ckb_types::packed::CellOutput",
                "cell_dep": "ckb_types::packed::CellDep",
                "out_point": "ckb_types::packed::OutPoint",
                "script": "ckb_types::packed::Script",
                "witness_args": "ckb_types::packed::WitnessArgs",
                "realizer": "cellscript-ckb-adapter via ckb-sdk-rust or CCC",
            },
            "cell_deps": [],
            "header_deps": [],
            "inputs": [],
            "outputs": [],
            "outputs_data": [],
            "witnesses": [],
            "required_evidence": [
                "live_cell_resolution",
                "outputs_data_pairing",
                "witness_args_placement",
                "celldep_resolution",
                "occupied_capacity",
                "fee_and_change",
                "estimate_cycles",
                "tx_pool_acceptance"
            ],
            "notes": [
                "This is a headless draft template produced from compiler metadata.",
                "A builder adapter must resolve live cells, fill args, calculate fees/capacity, dry-run, sign, and submit."
            ]
        });
        let resolved_tx_required_fields = serde_json::json!([
            "schema",
            "state",
            "metadata_hash",
            "artifact_hash",
            "deployment_ref",
            "action_selector",
            "inputs",
            "outputs",
            "outputs_data",
            "witnesses",
            "cell_deps",
            "header_deps",
            "capacity_evidence",
            "fee_policy",
            "change_policy",
            "lineage"
        ]);
        let acceptance_report_template = serde_json::json!({
            "schema": "cellscript-ckb-action-acceptance-report-v0.19",
            "state": "AcceptedActionTx",
            "metadata_hash": metadata_hash,
            "artifact_hash": result.metadata.artifact_hash,
            "deployment_ref": serde_json::Value::Null,
            "action_selector": action.name,
            "ckb_vm_execution": serde_json::Value::Null,
            "estimate_cycles": serde_json::Value::Null,
            "tx_pool_acceptance": serde_json::Value::Null,
            "submitted_tx_hash": serde_json::Value::Null,
            "serialized_tx_size_bytes": serde_json::Value::Null,
            "occupied_capacity_shannons": serde_json::Value::Null,
            "fee_shannons": serde_json::Value::Null,
            "lineage": [],
            "known_limitations": [
                "Template only: adapter must fill live cells, deployment refs, packed transaction bytes, signer policy, and node evidence."
            ],
        });
        let adapter_contract = serde_json::json!({
            "schema": "cellscript-ckb-adapter-contract-v0.19",
            "headless": true,
            "compiler_core_dependency": "no-ckb-sdk-rust",
            "compiler_output_state": "ActionPlan",
            "adapter_output_state": "ResolvedActionTx",
            "accepted_output_state": "AcceptedActionTx",
            "transaction_realizer": "ckb-sdk-rust-or-CCC-adapter",
            "must_not_infer_protocol_semantics_from_action_name": true,
            "must_keep_signer_authority_explicit": true,
            "must_preserve_outputs_outputs_data_pairing": true,
            "must_emit_lineage": true,
            "witness_policy": {
                "entry_payload_abi": ENTRY_WITNESS_ABI,
                "placement_abi": ENTRY_WITNESS_PLACEMENT_ABI,
                "entry_payload_owner": "compiler",
                "final_witness_args_owner": "adapter",
                "default_action_payload_field": ENTRY_WITNESS_PLACEMENT_FIELD,
                "runtime_source": ENTRY_WITNESS_PLACEMENT_SOURCE,
                "raw_v1_compatible": false,
                "lock_signature_policy": "explicit-adapter-owned-do-not-overwrite",
                "placement_requires_deployment_role": true,
            },
            "acceptance_methods": ["estimate_cycles", "test_tx_pool_accept", "send_transaction_optional"],
            "not_proven_by_this_plan": ["live_cell_availability", "ckb_vm_execution", "tx_pool_acceptance", "submission"],
            "resolved_tx_required_fields": resolved_tx_required_fields,
            "acceptance_report_template": acceptance_report_template,
        });
        let preview = serde_json::json!({
            "format": "cellscript-action-preview-v1",
            "action": action.name,
            "summary": format!("Build a CKB transaction for CellScript action {}", action.name),
            "consumes": action.transaction_runtime_input_requirements,
            "creates": action.create_set,
            "transitions": action.mutate_set,
            "witnesses": {
                "selector": action.name,
                "args": action.params,
            },
            "warnings": [
                "Builder preview is metadata-backed; live cell freshness and final fee/capacity must be checked at build time."
            ],
            "estimatedFee": serde_json::Value::Null,
            "requiredSigners": []
        });
        let plan = serde_json::json!({
            "status": "ok",
            "policy": "cellscript-action-builder-plan-v1",
            "headless": true,
            "ui_scope": "none",
            "input": input_path.display().to_string(),
            "action": action.name,
            "target_profile": result.metadata.target_profile.name,
            "artifact_hash": result.metadata.artifact_hash,
            "entry_witness_abi": {
                "required": !action.params.is_empty(),
                "params": action.params,
                "constraints": entry_constraints,
            },
            "builder_requirements": {
                "created_outputs": action.create_set,
                "mutated_outputs": action.mutate_set,
                "read_refs": action.read_refs,
                "verifier_obligations": action.verifier_obligations,
                "runtime_input_requirements": action.transaction_runtime_input_requirements,
                "action_scan_selectors": action_scan_selectors,
                "fail_closed_runtime_features": action.fail_closed_runtime_features,
            },
            "ckb": ckb_contract,
            "transaction_draft": transaction_draft,
            "adapter_contract": adapter_contract,
            "action_scan_selectors": action_scan_selectors,
            "preview": preview,
            "constraints_status": result.metadata.constraints.status,
            "constraints_failures": result.metadata.constraints.failures,
            "constraints_warnings": result.metadata.constraints.warnings,
        });
        let output_value = if args.fabric_intent {
            cellfabric_intent_envelope_json(&result.metadata, action, &plan, &input_path, &metadata_hash)?
        } else {
            plan
        };
        let json = serde_json::to_string_pretty(&output_value).map_err(|error| {
            crate::error::CompileError::without_span(format!("failed to serialize action build output: {}", error))
        })?;

        if let Some(output_path) = args.output {
            if let Some(parent) = output_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&output_path, json)?;
            let label = if args.fabric_intent { "CellFabric intent envelope generated" } else { "Action build plan generated" };
            println!("{}", label.green());
            println!("  Output: {}", output_path.display());
        } else if args.json {
            println!("{}", json);
        } else if args.fabric_intent {
            println!("CellFabric intent envelope: {}", action.name);
            println!("  Target profile: {}", result.metadata.target_profile.name);
            println!("  Status: requires-runtime-binding");
            println!("  App conflict key templates: {}", cellfabric_app_conflict_key_templates(&result.metadata.module, action).len());
            println!("  Embedded action plan: yes");
        } else {
            println!("Action build plan: {}", action.name);
            println!("  Target profile: {}", result.metadata.target_profile.name);
            println!("  Constraints: {}", result.metadata.constraints.status);
            println!("  Created outputs: {}", action.create_set.len());
            println!("  Mutated outputs: {}", action.mutate_set.len());
            println!("  Runtime input requirements: {}", action.transaction_runtime_input_requirements.len());
        }
        Ok(())
    }

    fn gen_builder(args: GenBuilderArgs) -> Result<()> {
        if args.target != "typescript" {
            return Err(crate::error::CompileError::without_span(format!(
                "unsupported builder target '{}'; supported targets: typescript",
                args.target
            )));
        }

        let metadata = if let Some(metadata_path) = args.metadata.as_deref() {
            read_metadata_json(metadata_path)?
        } else {
            let input_path = args.input.clone().unwrap_or_else(|| PathBuf::from("."));
            let input = Utf8Path::from_path(&input_path).ok_or_else(|| {
                crate::error::CompileError::without_span(format!("path '{}' is not valid UTF-8", input_path.display()))
            })?;
            let options = CompileOptions {
                edition: crate::CURRENT_EDITION,
                opt_level: 1,
                output: None,
                debug: false,
                target: None,
                target_profile: args.target_profile.clone().or_else(|| Some("ckb".to_string())),
                primitive_compat: None,
            };
            if let Some(name) = args.artifact.as_deref() {
                crate::compile_path_with_artifact_name(input, options, name, ExecutableSurfacePolicy::DenyFailClosed)?.metadata
            } else {
                compile_path(input, options)?.metadata
            }
        };

        if args.artifact.is_some() || metadata.runtime.policy_artifact.is_some() {
            crate::validate_compile_metadata(&metadata, ArtifactFormat::from_display_name(&metadata.artifact_format)?)?;
            let policy = metadata.runtime.policy_artifact.as_ref().ok_or_else(|| {
                CompileError::without_span("gen-builder --artifact requires metadata for an explicitly selected policy artifact")
            })?;
            if args.artifact.as_deref().is_some_and(|name| name != policy.declaration.name) {
                return Err(CompileError::without_span("gen-builder --artifact does not match the selected metadata declaration"));
            }
        }

        let metadata_hash = hash_json_value("metadata", &metadata)?;
        let selected_actions = selected_builder_actions(&metadata, args.action.as_deref())?;
        let locked_identity = if let Some(lockfile_path) = args.lockfile.as_deref() {
            Some(verify_builder_lockfile_identity(lockfile_path, &metadata, &metadata_hash)?)
        } else {
            None
        };
        let deployment_identity = if let Some(deployed_path) = args.deployed.as_deref() {
            let lockfile_path = args.lockfile.as_deref().ok_or_else(|| {
                crate::error::CompileError::without_span("gen-builder --deployed requires --lockfile for deployment identity binding")
            })?;
            Some(verify_builder_deployment_identity(
                lockfile_path,
                deployed_path,
                &metadata,
                &metadata_hash,
                args.deployment_network.as_deref(),
            )?)
        } else {
            None
        };
        let output_dir = args.output.unwrap_or_else(|| PathBuf::from("target").join("cellscript-builder").join("typescript"));
        let package_name = args.package_name.unwrap_or_else(|| default_builder_package_name(&metadata));
        let summary = write_typescript_builder_package(
            &output_dir,
            &package_name,
            &metadata,
            &metadata_hash,
            &selected_actions,
            locked_identity.as_ref(),
            deployment_identity.as_ref(),
            args.lockfile.as_deref(),
            args.deployed.as_deref(),
        )?;

        CommandOutcome {
            machine: summary,
            human_lines: vec![
                "TypeScript action builder generated".green().to_string(),
                format!("  Output: {}", output_dir.display()),
                format!("  Package: {}", package_name),
                format!("  Actions: {}", selected_actions.len()),
            ],
        }
        .emit(args.json)
    }

    /// Encode witness bytes for the generated `_cellscript_entry` wrapper.
    fn entry_witness(args: EntryWitnessArgs) -> Result<()> {
        if args.action.is_some() && args.lock.is_some() {
            return Err(crate::error::CompileError::without_span("entry-witness accepts either --action or --lock, not both"));
        }

        let input_path = args.input.clone().unwrap_or_else(|| PathBuf::from("."));
        let input = Utf8Path::from_path(&input_path)
            .ok_or_else(|| crate::error::CompileError::without_span(format!("path '{}' is not valid UTF-8", input_path.display())))?;
        if args.artifact.is_some() {
            return policy_entry_witness(&args, input);
        }
        if args.script_hash.is_some() {
            return Err(CompileError::without_span("entry-witness --script-hash requires --artifact"));
        }
        let result = compile_path(
            input,
            CompileOptions {
                edition: crate::CURRENT_EDITION,
                opt_level: 0,
                output: None,
                debug: false,
                target: args.target,
                target_profile: args.target_profile,
                primitive_compat: None,
            },
        )?;

        let selected = select_entry_witness_metadata(&result.metadata, args.action.as_deref(), args.lock.as_deref())?;
        if selected.params.is_empty() {
            return Err(crate::error::CompileError::without_span(format!(
                "{} '{}' has no parameters; `_cellscript_entry` witness ABI is only emitted for parameterized entries",
                selected.kind, selected.name
            )));
        }

        let payload_params = selected
            .params
            .iter()
            .filter(|param| {
                !param.lock_args_data_source
                    && !param.cell_bound_abi
                    && !param.ty.starts_with('&')
                    && !selected.runtime_bound_param_names.contains(&param.name)
            })
            .collect::<Vec<_>>();
        if args.args.len() != payload_params.len() {
            return Err(crate::error::CompileError::without_span(format!(
                "{} '{}' expects {} witness payload arg(s), got {}",
                selected.kind,
                selected.name,
                payload_params.len(),
                args.args.len()
            )));
        }

        let witness_args = payload_params
            .iter()
            .zip(args.args.iter())
            .map(|(param, value)| parse_entry_witness_arg(param, value))
            .collect::<Result<Vec<_>>>()?;
        let witness = crate::encode_entry_witness_args_for_params_with_runtime_bound(
            selected.params,
            &witness_args,
            &selected.runtime_bound_param_names,
        )
        .map_err(|error| crate::error::CompileError::without_span(format!("failed to encode entry witness: {}", error)))?;
        let witness_hex = crate::hex_encode(&witness);

        if let Some(output_path) = &args.output {
            if let Some(parent) = output_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(output_path, &witness)?;
        }

        let payload_param_names = payload_params.iter().map(|param| param.name.as_str()).collect::<Vec<_>>();
        let human_lines = if let Some(output_path) = &args.output {
            vec![
                "Entry witness encoded".green().to_string(),
                format!("  ABI: {}", ENTRY_WITNESS_ABI),
                format!("  Entry: {} {}", selected.kind, selected.name),
                format!("  Output: {}", output_path.display()),
                format!("  Hex: {}", witness_hex),
            ]
        } else {
            vec![witness_hex.clone()]
        };
        CommandOutcome {
            machine: serde_json::json!({
                "status": "ok",
                "abi": ENTRY_WITNESS_ABI,
                "placement_abi": ENTRY_WITNESS_PLACEMENT_ABI,
                "witness_args_field": ENTRY_WITNESS_PLACEMENT_FIELD,
                "witness_source": ENTRY_WITNESS_PLACEMENT_SOURCE,
                "raw_v1_compatible": false,
                "entry_kind": selected.kind,
                "entry": selected.name,
                "witness_hex": witness_hex,
                "witness_size_bytes": witness.len(),
                "payload_args": witness_args.len(),
                "payload_params": payload_param_names,
                "output": args.output.as_ref().map(|path| path.display().to_string()),
            }),
            human_lines,
        }
        .emit(args.json)
    }

    fn receipt(args: ReceiptArgs) -> Result<()> {
        let input_path = args.input.clone().unwrap_or_else(|| PathBuf::from("."));
        let input = Utf8Path::from_path(&input_path)
            .ok_or_else(|| crate::error::CompileError::without_span(format!("path '{}' is not valid UTF-8", input_path.display())))?;
        let input_path = resolve_input_path(input)?;
        let compile_result = compile_path(
            &input_path,
            CompileOptions {
                edition: crate::CURRENT_EDITION,
                target: args.target.clone(),
                target_profile: args.target_profile.clone(),
                ..CompileOptions::default()
            },
        )?;
        let receipt = compile_receipt_json(&compile_result.metadata)?;
        if let Some(parent) = args.output.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(
            &args.output,
            serde_json::to_vec_pretty(&receipt).map_err(|error| {
                crate::error::CompileError::without_span(format!("failed to serialize compile receipt: {}", error))
            })?,
        )?;
        CommandOutcome {
            machine: serde_json::json!({
                "status": "ok",
                "receipt": args.output.display().to_string(),
                "schema": receipt["schema"],
                "artifact_hash": receipt["artifact_hash"],
                "metadata_hash": receipt["metadata_hash"],
                "signature_count": 0,
                "unsigned_advisory": true,
            }),
            human_lines: vec![
                "Compile receipt written".green().to_string(),
                format!("  Receipt: {}", args.output.display()),
                format!("  Artifact hash: {}", receipt["artifact_hash"].as_str().unwrap_or("missing")),
                format!("  Metadata hash: {}", receipt["metadata_hash"].as_str().unwrap_or("missing")),
                "  Signatures: unsigned advisory".to_string(),
            ],
        }
        .emit(args.json)
    }

    fn sign_receipt(args: SignReceiptArgs) -> Result<()> {
        let mut receipt = read_json_value(&args.receipt)?;
        validate_compile_receipt_schema(&receipt)?;
        let payload_hash = compile_receipt_payload_hash(&receipt)?;
        let key_bytes = read_ed25519_pkcs8_key_arg(&args.key)?;
        let key_pair = ring::signature::Ed25519KeyPair::from_pkcs8(&key_bytes)
            .map_err(|error| crate::error::CompileError::without_span(format!("failed to load Ed25519 private key: {:?}", error)))?;
        let signature = key_pair.sign(payload_hash.as_bytes());
        let signature_entry = serde_json::json!({
            "role": validate_receipt_signature_role(&args.role)?,
            "algorithm": "ed25519",
            "public_key": format!("ed25519-pk:{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key_pair.public_key().as_ref())),
            "payload_hash": payload_hash,
            "signature": format!("ed25519-sig:{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.as_ref())),
        });
        let object = receipt.as_object_mut().ok_or_else(|| {
            crate::error::CompileError::without_span("compile receipt must be a JSON object before it can be signed")
        })?;
        match object.get_mut("signatures") {
            Some(serde_json::Value::Array(signatures)) => signatures.push(signature_entry.clone()),
            Some(_) => {
                return Err(crate::error::CompileError::without_span(
                    "compile receipt signatures field must be an array before it can be signed",
                ));
            }
            None => {
                object.insert("signatures".to_string(), serde_json::json!([signature_entry.clone()]));
            }
        }

        let output_path = args.output.unwrap_or_else(|| args.receipt.clone());
        if let Some(parent) = output_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(
            &output_path,
            serde_json::to_vec_pretty(&receipt)
                .map_err(|error| crate::error::CompileError::without_span(format!("failed to serialize signed receipt: {}", error)))?,
        )?;

        CommandOutcome {
            machine: serde_json::json!({
                "status": "ok",
                "receipt": output_path.display().to_string(),
                "role": signature_entry["role"],
                "algorithm": signature_entry["algorithm"],
                "public_key": signature_entry["public_key"],
                "payload_hash": signature_entry["payload_hash"],
            }),
            human_lines: vec![
                "Compile receipt signed".green().to_string(),
                format!("  Receipt: {}", output_path.display()),
                format!("  Role: {}", signature_entry["role"].as_str().unwrap_or("unknown")),
                format!("  Payload hash: {}", signature_entry["payload_hash"].as_str().unwrap_or("missing")),
            ],
        }
        .emit(args.json)
    }

    fn verify_receipt(args: VerifyReceiptArgs) -> Result<()> {
        let receipt = read_json_value(&args.receipt)?;
        let artifact_bytes = std::fs::read(&args.artifact).map_err(|error| {
            crate::error::CompileError::without_span(format!("failed to read artifact '{}': {}", args.artifact.display(), error))
        })?;
        let metadata_bytes = std::fs::read(&args.metadata).map_err(|error| {
            crate::error::CompileError::without_span(format!("failed to read metadata '{}': {}", args.metadata.display(), error))
        })?;
        let metadata: CompileMetadata = serde_json::from_slice(&metadata_bytes).map_err(|error| {
            crate::error::CompileError::without_span(format!("failed to parse metadata '{}': {}", args.metadata.display(), error))
        })?;
        let validated = validate_artifact_metadata(artifact_bytes, metadata)?;
        let report = verify_compile_receipt_against_metadata(&receipt, &validated.metadata)?;

        let signature_line = if report.unsigned_advisory {
            "  Signatures: unsigned advisory".to_string()
        } else {
            format!("  Signatures verified: {}", report.signatures_verified)
        };
        CommandOutcome {
            machine: serde_json::json!({
                "status": "ok",
                "receipt": args.receipt.display().to_string(),
                "metadata": args.metadata.display().to_string(),
                "artifact": args.artifact.display().to_string(),
                "payload_hash": report.payload_hash,
                "signatures_verified": report.signatures_verified,
                "unsigned_advisory": report.unsigned_advisory,
            }),
            human_lines: vec![
                "Compile receipt verification succeeded".green().to_string(),
                format!("  Receipt: {}", args.receipt.display()),
                format!("  Artifact: {}", args.artifact.display()),
                format!("  Metadata: {}", args.metadata.display()),
                format!("  Payload hash: {}", report.payload_hash),
                signature_line,
            ],
        }
        .emit(args.json)
    }

    fn verify_artifact(args: VerifyArtifactArgs) -> Result<()> {
        let artifact_path = Utf8Path::from_path(&args.artifact).ok_or_else(|| {
            crate::error::CompileError::without_span(format!("artifact path '{}' is not valid UTF-8", args.artifact.display()))
        })?;
        let metadata_path = match args.metadata.as_ref() {
            Some(path) => path.clone(),
            None => default_metadata_path_for_artifact(artifact_path).into_std_path_buf(),
        };

        let artifact_bytes = std::fs::read(&args.artifact).map_err(|error| {
            crate::error::CompileError::without_span(format!("failed to read artifact '{}': {}", args.artifact.display(), error))
        })?;
        let metadata_bytes = std::fs::read(&metadata_path).map_err(|error| {
            crate::error::CompileError::without_span(format!("failed to read metadata '{}': {}", metadata_path.display(), error))
        })?;
        let metadata: CompileMetadata = serde_json::from_slice(&metadata_bytes).map_err(|error| {
            crate::error::CompileError::without_span(format!("failed to parse metadata '{}': {}", metadata_path.display(), error))
        })?;
        let (checker_report, lowering_record_path, source_map_path) = if metadata.artifact_format == "RISC-V ELF" {
            let lowering_record_path = args
                .lowering_record
                .clone()
                .unwrap_or_else(|| crate::lowering_record_output_path_from_artifact(artifact_path).into_std_path_buf());
            let source_map_path = args
                .source_map
                .clone()
                .unwrap_or_else(|| crate::source_map_output_path_from_artifact(artifact_path).into_std_path_buf());
            let lowering_record_bytes = std::fs::read(&lowering_record_path).map_err(|error| {
                crate::error::CompileError::without_span(format!(
                    "failed to read lowering record '{}': {}",
                    lowering_record_path.display(),
                    error
                ))
            })?;
            let source_map_bytes = std::fs::read(&source_map_path).map_err(|error| {
                crate::error::CompileError::without_span(format!(
                    "failed to read source map '{}': {}",
                    source_map_path.display(),
                    error
                ))
            })?;
            let report = cellscript_artifact_checker::check_bundle(
                &artifact_bytes,
                &metadata_bytes,
                &lowering_record_bytes,
                &source_map_bytes,
                &crate::CheckerBudgets::default(),
            )
            .map_err(|error| crate::error::CompileError::without_span(error.to_string()))?;
            (Some(report), Some(lowering_record_path), Some(source_map_path))
        } else {
            if args.lowering_record.is_some() || args.source_map.is_some() {
                return Err(crate::error::CompileError::without_span(
                    "--lowering-record/--source-map are only valid for RISC-V ELF artifacts",
                ));
            }
            (None, None, None)
        };
        let result = validate_artifact_metadata(artifact_bytes, metadata)?;
        if args.verify_sources {
            validate_source_units_on_disk(&result.metadata)?;
        }
        validate_expected_target_profile(result.metadata.target_profile.name.as_str(), args.expect_target_profile.as_deref())?;
        validate_expected_metadata_hash(
            "artifact_hash",
            result.metadata.artifact_hash.as_deref(),
            args.expect_artifact_hash.as_deref(),
        )?;
        validate_expected_metadata_hash("source_hash", result.metadata.source_hash.as_deref(), args.expect_source_hash.as_deref())?;
        validate_expected_metadata_hash(
            "source_content_hash",
            result.metadata.source_content_hash.as_deref(),
            args.expect_source_content_hash.as_deref(),
        )?;
        validate_check_policy(
            &result.metadata,
            &CheckArgs {
                production: args.production,
                deny_fail_closed: args.deny_fail_closed,
                deny_ckb_runtime: args.deny_ckb_runtime,
                deny_runtime_obligations: args.deny_runtime_obligations,
                primitive_compat: args.primitive_compat,
                ..CheckArgs::default()
            },
        )?;
        let receipt_report = if let Some(receipt_path) = args.receipt.as_deref() {
            let receipt = read_json_value(receipt_path)?;
            Some(verify_compile_receipt_against_metadata(&receipt, &result.metadata)?)
        } else {
            None
        };

        let expected_target_profile_verified = args.expect_target_profile.is_some();
        let expected_hashes_verified =
            args.expect_artifact_hash.is_some() || args.expect_source_hash.is_some() || args.expect_source_content_hash.is_some();
        let policy_verified = args.production || args.deny_fail_closed || args.deny_ckb_runtime || args.deny_runtime_obligations;

        if args.json {
            let mut summary = serde_json::json!({
                "status": "ok",
                "artifact": args.artifact.display().to_string(),
                "metadata": metadata_path.display().to_string(),
                "metadata_schema_version": result.metadata.metadata_schema_version,
                "metadata_schema_versions": metadata_schema_versions_json(&result.metadata),
                "compiler_version": result.metadata.compiler_version,
                "artifact_format": result.artifact_format.display_name(),
                "target_profile": result.metadata.target_profile.name.as_str(),
                "artifact_hash": result.metadata.artifact_hash,
                "artifact_size_bytes": result.artifact_bytes.len(),
                "source_hash": result.metadata.source_hash,
                "source_content_hash": result.metadata.source_content_hash,
                "source_units": result.metadata.source_units.len(),
                "verifier_obligations": result.metadata.runtime.verifier_obligations.len(),
                "runtime_required_verifier_obligations": runtime_required_obligation_count(&result.metadata),
                "fail_closed_verifier_obligations": fail_closed_obligation_count(&result.metadata),
                "runtime_required_transaction_invariants": runtime_required_transaction_invariant_count(&result.metadata),
                "runtime_required_transaction_invariant_checked_subconditions": runtime_required_transaction_invariant_checked_subcondition_count(&result.metadata),
                "runtime_required_transaction_invariant_checked_subcondition_summaries": transaction_invariant_checked_subcondition_summaries(&result.metadata),
                "transaction_runtime_input_requirements": transaction_runtime_input_requirement_count(&result.metadata),
                "transaction_runtime_input_requirement_summaries": transaction_runtime_input_requirement_summaries(&result.metadata),
                "checked_transaction_runtime_input_requirements": transaction_runtime_input_requirement_count_by_status(&result.metadata, "checked-runtime"),
                "checked_transaction_runtime_input_requirement_summaries": transaction_runtime_input_requirement_summaries_by_status(&result.metadata, "checked-runtime"),
                "runtime_required_transaction_runtime_input_requirements": transaction_runtime_input_requirement_count_by_status(&result.metadata, "runtime-required"),
                "runtime_required_transaction_runtime_input_requirement_summaries": transaction_runtime_input_requirement_summaries_by_status(&result.metadata, "runtime-required"),
                "runtime_required_transaction_runtime_input_blockers": transaction_runtime_input_blocker_count_by_status(&result.metadata, "runtime-required"),
                "runtime_required_transaction_runtime_input_blocker_summaries": transaction_runtime_input_blocker_summaries_by_status(&result.metadata, "runtime-required"),
                "runtime_required_transaction_runtime_input_blocker_classes": transaction_runtime_input_blocker_class_count_by_status(&result.metadata, "runtime-required"),
                "runtime_required_transaction_runtime_input_blocker_class_summaries": transaction_runtime_input_blocker_class_summaries_by_status(&result.metadata, "runtime-required"),
                "checked_pool_invariant_families": checked_pool_invariant_family_count(&result.metadata),
                "runtime_required_pool_invariant_families": runtime_required_pool_invariant_family_count(&result.metadata),
                "runtime_required_pool_invariant_blocker_classes": pool_invariant_family_blocker_class_count(&result.metadata, "runtime-required"),
                "runtime_required_pool_invariant_blocker_class_summaries": pool_invariant_family_blocker_class_summaries(&result.metadata, "runtime-required"),
                "pool_runtime_input_requirements": pool_runtime_input_requirement_count(&result.metadata),
                "pool_runtime_input_requirement_summaries": pool_runtime_input_requirement_summaries(&result.metadata),
                "sources_verified": args.verify_sources,
                "expected_target_profile_verified": expected_target_profile_verified,
                "expected_hashes_verified": expected_hashes_verified,
                "policy_verified": policy_verified,
                "constraints": &result.metadata.constraints,
            });
            if let Some(object) = summary.as_object_mut() {
                object.insert(
                    "lowering_record".to_string(),
                    serde_json::json!(lowering_record_path.as_ref().map(|path| path.display().to_string())),
                );
                object.insert(
                    "source_map".to_string(),
                    serde_json::json!(source_map_path.as_ref().map(|path| path.display().to_string())),
                );
                object.insert("binding_verification".to_string(), serde_json::json!("verified"));
                object.insert(
                    "structural_verification".to_string(),
                    serde_json::json!(if checker_report.is_some() { "verified" } else { "not-applicable" }),
                );
                object.insert(
                    "lowering_record_verification".to_string(),
                    serde_json::json!(if checker_report.is_some() { "verified" } else { "not-applicable" }),
                );
                object.insert("ckb_vm_evidence".to_string(), serde_json::json!("not-executed"));
                object.insert("chain_evidence".to_string(), serde_json::json!("not-provided"));
                object.insert("semantic_equivalence_claimed".to_string(), serde_json::json!(false));
                object.insert("checker_report".to_string(), serde_json::json!(&checker_report));
                object.insert("receipt_verified".to_string(), serde_json::json!(receipt_report.is_some()));
                object.insert(
                    "receipt_payload_hash".to_string(),
                    serde_json::json!(receipt_report.as_ref().map(|report| report.payload_hash.as_str())),
                );
                object.insert(
                    "receipt_signatures_verified".to_string(),
                    serde_json::json!(receipt_report.as_ref().map(|report| report.signatures_verified).unwrap_or(0)),
                );
                object.insert(
                    "receipt_unsigned_advisory".to_string(),
                    serde_json::json!(receipt_report.as_ref().map(|report| report.unsigned_advisory).unwrap_or(false)),
                );
            }
            let json = serde_json::to_string_pretty(&summary).map_err(|error| {
                crate::error::CompileError::without_span(format!("failed to serialize verification summary: {}", error))
            })?;
            println!("{}", json);
            return Ok(());
        }

        println!("{}", "Artifact verification succeeded".green());
        println!("  Artifact: {}", args.artifact.display());
        println!("  Metadata: {}", metadata_path.display());
        println!("  Metadata schema: {}", result.metadata.metadata_schema_version);
        println!(
            "  Metadata schema components: source={}, artifact={}, constraints={}",
            result.metadata.source_metadata_schema_version,
            result.metadata.artifact_metadata_schema_version,
            result.metadata.constraints_metadata_schema_version
        );
        println!("  Compiler: {}", result.metadata.compiler_version);
        println!("  Format: {}", result.artifact_format.display_name());
        println!("  Target profile: {}", result.metadata.target_profile.name);
        println!("  Hash: {}", result.metadata.artifact_hash.as_deref().unwrap_or("missing"));
        println!("  Size: {} bytes", result.artifact_bytes.len());
        println!("  Binding verification: verified");
        if checker_report.is_some() {
            println!("  Structural verification: verified");
            println!("  Lowering-record verification: verified");
            if let Some(path) = lowering_record_path {
                println!("  Lowering record: {}", path.display());
            }
            if let Some(path) = source_map_path {
                println!("  Source map: {}", path.display());
            }
        } else {
            println!("  Structural verification: not applicable to assembly");
            println!("  Lowering-record verification: not applicable to assembly");
        }
        println!("  CKB-VM evidence: not executed");
        println!("  Chain evidence: not provided");
        println!("  Semantic equivalence: not claimed");
        if expected_target_profile_verified {
            println!("  Expected target profile: verified");
        }
        if expected_hashes_verified {
            println!("  Expected hashes: verified");
        }
        if args.verify_sources {
            println!("  Sources: verified {} unit(s)", result.metadata.source_units.len());
        }
        if policy_verified {
            println!("  Policy: verified");
        }
        if let Some(report) = receipt_report {
            println!("  Receipt: verified");
            println!("  Receipt payload hash: {}", report.payload_hash);
            if report.unsigned_advisory {
                println!("  Receipt signatures: unsigned advisory");
            } else {
                println!("  Receipt signatures verified: {}", report.signatures_verified);
            }
        }
        Ok(())
    }

    fn protocol_bundle_check(args: ProtocolBundleCheckArgs) -> Result<()> {
        let report = crate::protocol_bundle::check_protocol_bundle_file(&args.manifest)?;
        let machine = serde_json::to_value(&report).map_err(|error| {
            crate::error::CompileError::without_span(format!("failed to serialize ProtocolBundle report: {}", error))
        })?;
        if let Some(output) = args.output.as_deref() {
            if let Some(parent) = output.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(
                output,
                serde_json::to_vec_pretty(&report).map_err(|error| {
                    crate::error::CompileError::without_span(format!("failed to serialize ProtocolBundle report: {}", error))
                })?,
            )?;
        }

        let human_lines = vec![
            format!("ProtocolBundle check: {}", report.status),
            format!("  Bundle hash: {}", report.bundle_hash),
            format!("  Artifacts: {}", report.bundle.artifacts.len()),
            format!("  Conflicts: {}", report.conflicts.len()),
            "  Runtime evidence: not executed".to_string(),
        ];
        let failed = report.status != "ok";
        let outcome = CommandOutcome { machine, human_lines };
        if failed {
            Err(outcome.failure(format!("ProtocolBundle has {} unresolved conflict(s)", report.conflicts.len())))
        } else {
            outcome.emit(args.json)
        }
    }

    fn run(args: RunArgs) -> Result<()> {
        let opt_level = if args.release { 3 } else { 0 };
        let compile_result = compile_path(
            ".",
            CompileOptions {
                edition: crate::CURRENT_EDITION,
                opt_level,
                output: None,
                debug: false,
                target: Some("riscv64-elf".to_string()),
                target_profile: None,
                primitive_compat: None,
            },
        );

        if args.simulate {
            let result = compile_result?;
            return Self::run_simulate(&result, &args);
        }

        #[cfg(feature = "vm-runner")]
        {
            let result = compile_result?;

            let parameterized_entries = result
                .metadata
                .actions
                .iter()
                .filter(|action| !action.params.is_empty())
                .map(|action| format!("action {}", action.name))
                .chain(result.metadata.locks.iter().filter(|lock| !lock.params.is_empty()).map(|lock| format!("lock {}", lock.name)))
                .collect::<Vec<_>>();
            if !parameterized_entries.is_empty() {
                return Err(crate::error::CompileError::without_span(format!(
                    "cellc run executes only no-argument pure ELF entrypoints; {} requires transaction/parameter ABI context; use --simulate explicitly for development interpretation",
                    parameterized_entries.join(", ")
                )));
            }

            if result.metadata.runtime.ckb_runtime_required {
                return Err(crate::error::CompileError::without_span(format!(
                    "cellc run cannot provide CKB transaction/syscall context required by {}; use --simulate explicitly or an executable transaction scenario",
                    result.metadata.runtime.ckb_runtime_features.join(", ")
                )));
            }

            if !result.metadata.runtime.standalone_runner_compatible {
                return Err(crate::error::CompileError::without_span(
                    "cellc run requires a standalone-compatible pure ELF; use --simulate explicitly or an executable transaction scenario",
                ));
            }

            let vm_args = args.args.into_iter().map(|arg| arg.into_bytes()).collect::<Vec<_>>();
            let cycles = run_elf_in_ckb_vm(&result.artifact_bytes, &vm_args)?;
            RunOutcome {
                status: "ok",
                mode: "ckb-vm",
                artifact_format: result.artifact_format.display_name().to_string(),
                entry: run_entry_outcome(&result.metadata),
                cycles: Some(cycles),
                steps: None,
                has_cell_operations: None,
                result: None,
                trace: Vec::new(),
            }
            .emit(args.json)
        }

        #[cfg(not(feature = "vm-runner"))]
        {
            let mode = if args.release { "release" } else { "debug" };
            Self::experimental_command(
                "run",
                &format!(
                    "feature-gated VM backend is not enabled (requested {}, {} argument(s)); use --simulate for AST-level simulation or compile with --features vm-runner to execute",
                    mode,
                    args.args.len()
                ),
            )
        }
    }

    fn run_simulate(compile_result: &crate::CompileResult, args: &RunArgs) -> Result<()> {
        use crate::simulate::{SimValue, SimulateInterpreter};

        let modules = crate::load_modules_for_input(".")?;
        let module =
            modules.iter().find(|module| module.ast.name == compile_result.metadata.module).map(|module| &module.ast).ok_or_else(
                || {
                    crate::error::CompileError::without_span(format!(
                        "failed to load module '{}' for simulation",
                        compile_result.metadata.module
                    ))
                },
            )?;

        let entry = compile_result
            .metadata
            .actions
            .iter()
            .find(|a| a.name == "main")
            .or_else(|| compile_result.metadata.actions.iter().find(|a| a.params.is_empty()));

        let Some(entry) = entry else {
            return Err(crate::error::CompileError::without_span(
                "no suitable entry point found for simulation; define an action main() or a zero-argument action",
            ));
        };

        let mut interp = SimulateInterpreter::new(module, 100_000);
        let sim_args: Vec<SimValue> = Vec::new();
        let sim_result = interp
            .simulate_action(&entry.name, &sim_args)
            .map_err(|e| crate::error::CompileError::without_span(format!("simulation error: {}", e)))?;

        RunOutcome {
            status: "ok",
            mode: "simulate",
            artifact_format: compile_result.artifact_format.display_name().to_string(),
            entry: Some(RunEntryOutcome { kind: "action".to_string(), name: sim_result.entry_name }),
            cycles: None,
            steps: Some(sim_result.steps),
            has_cell_operations: Some(sim_result.has_cell_ops),
            result: Some(sim_result.return_value.to_string()),
            trace: sim_result.trace.iter().map(ToString::to_string).collect(),
        }
        .emit(args.json)
    }

    fn publish(args: PublishArgs) -> Result<()> {
        if let Some(manifest_path) = args.artifact_manifest.clone() {
            return publish_declared_artifact(args, &manifest_path);
        }
        let pm = PackageManager::new(".");
        let manifest = pm.read_manifest()?;
        let artifact = cellscript_artifact_descriptor(args.artifact_kind.as_deref())?;

        if args.dry_run {
            let mut issues = Vec::<String>::new();
            if manifest.package.name.is_empty() {
                issues.push("package name is empty".to_string());
            }
            if manifest.package.version.is_empty() {
                issues.push("package version is empty".to_string());
            }
            if manifest.package.description.is_empty() {
                issues.push("package description is missing".to_string());
            }
            if manifest.package.license.is_empty() {
                issues.push("package license is missing".to_string());
            }
            if manifest.package.repository.is_empty() {
                issues.push("package repository is missing".to_string());
            }
            if manifest.package.namespace.is_none() {
                issues.push("package namespace is missing (required for publishing)".to_string());
            }

            let entry_path = std::path::Path::new(".").join(&manifest.package.entry);
            if !entry_path.exists() {
                issues.push(format!("entry file '{}' does not exist", manifest.package.entry));
            }

            let compile_result = compile_path(".", CompileOptions::default());
            match compile_result {
                Ok(result) => {
                    println!("{}", "Publish dry-run passed".green());
                    println!("  Package: {} v{}", manifest.package.name, manifest.package.version);
                    println!("  Artifact: {} ({} bytes)", result.artifact_format.display_name(), result.artifact_bytes.len());
                }
                Err(e) => {
                    issues.push(format!("compilation failed: {}", e));
                }
            }

            if !issues.is_empty() {
                println!("{}", "Issues found:".yellow());
                for issue in &issues {
                    println!("  - {}", issue);
                }
                return Err(crate::error::CompileError::without_span(format!("publish dry-run found {} issue(s)", issues.len())));
            }

            Ok(())
        } else {
            let namespace = manifest.package.namespace.clone().ok_or_else(|| {
                crate::error::CompileError::without_span(
                    "package namespace is required for publishing; add namespace = \"<your-namespace>\" to [package] in Cell.toml",
                )
            })?;

            if manifest.package.name.is_empty() {
                return Err(crate::error::CompileError::without_span("package name is empty"));
            }
            if manifest.package.version.is_empty() {
                return Err(crate::error::CompileError::without_span("package version is empty"));
            }

            // Compute source_hash
            let source_hash = crate::package::registry::compute_source_hash(std::path::Path::new("."))?;

            // Compile to get build artifact hashes
            let result = compile_path(".", CompileOptions::default())?;

            // Build registry version entry
            let version_entry = build_publish_registry_version(&manifest, &result, &source_hash)?;

            if args.offline {
                // Offline fixture publish: update registry.json without touching the public write API.
                crate::package::registry::RegistryIndex::append_version(
                    std::path::Path::new("."),
                    &manifest.package.name,
                    &namespace,
                    version_entry,
                )?;

                println!("{}", "Published offline registry fixture".green());
                println!("  Package: {}/{} v{}", namespace, manifest.package.name, manifest.package.version);
                println!("  Source hash: {}", source_hash);
                println!();
                println!("  Audit/offline mirror next steps:");
                println!("    git add registry.json");
                println!("    git commit -m \"publish v{}\"", manifest.package.version);
                println!("    git tag v{}", manifest.package.version);
                println!("    git push --tags");
                return Ok(());
            }

            let api_base = resolve_registry_api_base(args.api_url)?;
            let registry_origin = registry_origin_from_api_base(&api_base)?;
            let endpoint = registry_publish_endpoint(&api_base, &namespace, &manifest.package.name);
            let registry_entry = build_publish_registry_entry(
                &manifest,
                &namespace,
                version_entry,
                &artifact,
                &result.metadata.public_interface,
                &result.metadata.interface_hash,
            )?;
            let payload = if let Some(payload_path) = args.payload.as_deref() {
                read_registry_publish_payload(payload_path)?
            } else {
                let capability_key_id = match args.capability_key_id.or_else(|| std::env::var("CELLSCRIPT_CAPABILITY_KEY_ID").ok()) {
                    Some(key_id) => key_id,
                    None if args.authorise => {
                        authorise_registry_publish_key(&api_base, &namespace, &manifest.package.name, &artifact.kind, args.no_open)?
                    }
                    None => {
                        return Err(crate::error::CompileError::without_span(format!(
                            "publishing {}/{} requires a wallet-authorised publishing key; run `cellc publish --authorise` for the continuous browser flow, or pass an existing --capability-key-id",
                            namespace, manifest.package.name
                        ))
                        .with_category(crate::error::CompileErrorCategory::Authentication));
                    }
                };
                let issued_at = current_utc_timestamp();
                let expires_at = utc_timestamp_after_seconds(10 * 60);
                let nonce = registry_publish_nonce(
                    &registry_origin,
                    &namespace,
                    &manifest.package.name,
                    &manifest.package.version,
                    &source_hash,
                    &capability_key_id,
                    &issued_at,
                );
                crate::package::registry::RegistryPublishPayload {
                    protocol: crate::package::registry::REGISTRY_PUBLISH_PROTOCOL.to_string(),
                    action: crate::package::registry::PUBLISH_ACTION.to_string(),
                    registry_origin: registry_origin.clone(),
                    namespace: namespace.clone(),
                    name: manifest.package.name.clone(),
                    version: manifest.package.version.clone(),
                    source_hash: source_hash.clone(),
                    manifest_hash: crate::package::registry::compute_package_manifest_hash(&manifest)?,
                    capability_key_id,
                    nonce,
                    issued_at,
                    expires_at,
                    cli_version: crate::VERSION.to_string(),
                    artifact: artifact.clone(),
                    registry_entry,
                }
            };
            validate_publish_payload_matches_local_package(
                &payload,
                &registry_origin,
                &namespace,
                &manifest,
                &source_hash,
                &result.metadata.public_interface,
                &result.metadata.interface_hash,
            )?;
            let canonical_payload = registry_publish_canonical_payload(&payload)?;

            if args.print_payload {
                let preview = serde_json::json!({
                    "endpoint": endpoint,
                    "payload": payload,
                    "canonical_payload": canonical_payload,
                });
                if args.json {
                    print_json(&preview)?;
                } else {
                    println!("{}", "Registry publish payload".green());
                    println!("  Endpoint: {}", endpoint);
                    println!("  Package: {}/{} v{}", namespace, manifest.package.name, manifest.package.version);
                    println!("  Source hash: {}", source_hash);
                    println!();
                    println!("Canonical payload to sign:");
                    println!("{}", preview["canonical_payload"].as_str().unwrap_or_default());
                }
                return Ok(());
            }

            let capability_signature =
                if let Some(signature) = args.capability_signature.or_else(|| std::env::var("CELLSCRIPT_CAPABILITY_SIGNATURE").ok()) {
                    signature
                } else {
                    sign_registry_publish_payload(&payload.capability_key_id, &canonical_payload)?
                };
            let source_snapshot =
                build_registry_source_snapshot(args.source_snapshot.as_deref(), std::path::Path::new("."), &manifest, &source_hash)?;
            let request = crate::package::registry::RegistryPublishRequest {
                payload,
                capability_signature: crate::package::registry::RegistryCapabilitySignature {
                    algorithm: "p256-sha256".to_string(),
                    signature: capability_signature,
                },
                source_snapshot,
            };
            let idempotency_key = resolve_registry_publish_idempotency_key(args.idempotency_key.as_deref(), &request)?;
            submit_registry_publish_request(&endpoint, &request, &idempotency_key, args.json)
        }
    }

    fn install(args: InstallArgs) -> Result<()> {
        let pm = PackageManager::new(".");

        let _manifest = pm.read_manifest()?;

        if let Some(git_url) = &args.git {
            let crate_name = args.crate_name.clone().unwrap_or_else(|| {
                git_url.trim_end_matches('/').trim_end_matches(".git").split('/').next_back().unwrap_or("unknown").to_string()
            });

            let dep = DetailedDependency {
                version: args.version.clone().unwrap_or_else(|| "*".to_string()),
                namespace: None,
                package: None,
                resolver: None,
                git: Some(git_url.clone()),
                branch: None,
                tag: None,
                rev: None,
                path: None,
                optional: false,
                features: Vec::new(),
                default_features: true,
                use_environment: None,
                environment_independent: false,
                allow_unverified: false,
                allow_quarantined: false,
            };

            pm.resolve_from_git(&crate_name, git_url, &dep)?;

            let mut manifest = pm.read_manifest()?;
            manifest.dependencies.insert(crate_name.clone(), Dependency::Detailed(dep));
            pm.write_manifest(&manifest)?;

            refresh_lockfile_from_manifest(std::path::Path::new("."))?;

            println!("{}", format!("Installed {} from git {}", crate_name, git_url).green());
            Ok(())
        } else if let Some(path) = &args.path {
            let crate_name =
                args.crate_name.clone().unwrap_or_else(|| path.file_name().unwrap_or_default().to_string_lossy().to_string());

            let dep = DetailedDependency {
                version: args.version.clone().unwrap_or_else(|| "*".to_string()),
                namespace: None,
                package: None,
                resolver: None,
                git: None,
                branch: None,
                tag: None,
                rev: None,
                path: Some(path.to_string_lossy().to_string()),
                optional: false,
                features: Vec::new(),
                default_features: true,
                use_environment: None,
                environment_independent: false,
                allow_unverified: false,
                allow_quarantined: false,
            };

            let manifest_for_check = pm.read_manifest()?;
            validate_not_self_dependency(&crate_name, &Dependency::Detailed(dep.clone()), &manifest_for_check)?;

            pm.resolve_from_path(&crate_name, &path.to_string_lossy())?;

            let mut manifest = pm.read_manifest()?;
            manifest.dependencies.insert(crate_name.clone(), Dependency::Detailed(dep));
            pm.write_manifest(&manifest)?;

            refresh_lockfile_from_manifest(std::path::Path::new("."))?;

            println!("{}", format!("Installed {} from path {}", crate_name, path.display()).green());
            Ok(())
        } else if let Some(crate_name) = &args.crate_name {
            // Support both:
            //   cellc install cellscript/amm@1.2.0   (Go-style combined format)
            //   cellc install amm --namespace cellscript --version 1.2.0
            let (resolved_name, resolved_namespace, resolved_version) = if args.namespace.is_none() && args.version.is_none() {
                // Try parsing namespace/name@version format
                if let Some((ns, rest)) = crate_name.split_once('/') {
                    if let Some((name, ver)) = rest.split_once('@') {
                        (name.to_string(), Some(ns.to_string()), Some(ver.to_string()))
                    } else {
                        (rest.to_string(), Some(ns.to_string()), None)
                    }
                } else if let Some((name, ver)) = crate_name.split_once('@') {
                    (name.to_string(), None, Some(ver.to_string()))
                } else {
                    (crate_name.clone(), None, None)
                }
            } else {
                (crate_name.clone(), args.namespace.clone(), args.version.clone())
            };

            let version = resolved_version.unwrap_or_else(|| "*".to_string());

            let _resolved = pm.resolve_from_registry_with_namespace_and_policy(
                &resolved_name,
                &version,
                resolved_namespace.as_deref(),
                crate::package::registry::RegistryResolutionPolicy {
                    allow_unverified: args.allow_unverified,
                    allow_quarantined: args.allow_quarantined,
                },
            )?;

            let dep = if resolved_namespace.is_some() || args.allow_unverified || args.allow_quarantined {
                Dependency::Detailed(DetailedDependency {
                    version,
                    namespace: resolved_namespace.clone(),
                    package: None,
                    resolver: None,
                    git: None,
                    branch: None,
                    tag: None,
                    rev: None,
                    path: None,
                    optional: false,
                    features: Vec::new(),
                    default_features: true,
                    use_environment: None,
                    environment_independent: false,
                    allow_unverified: args.allow_unverified,
                    allow_quarantined: args.allow_quarantined,
                })
            } else {
                Dependency::Simple(version)
            };

            let mut manifest = pm.read_manifest()?;
            validate_not_self_dependency(&resolved_name, &dep, &manifest)?;
            manifest.dependencies.insert(resolved_name.clone(), dep);
            pm.write_manifest(&manifest)?;

            refresh_lockfile_from_manifest(std::path::Path::new("."))?;

            let ns_display = resolved_namespace.as_deref().unwrap_or("<default>");
            println!("{}", format!("Installed {}/{} from registry", ns_display, resolved_name).green());
            Ok(())
        } else {
            refresh_lockfile_from_manifest(std::path::Path::new("."))?;

            println!("{}", "Dependencies resolved and lockfile updated".green());
            Ok(())
        }
    }

    fn update() -> Result<()> {
        refresh_lockfile_from_manifest(std::path::Path::new("."))?;
        let lockfile = Lockfile::read_from_root(std::path::Path::new("."))?.expect("lockfile was just written");
        if lockfile.dependencies.is_empty() {
            println!("{}", "No dependencies to update".green());
        } else {
            println!("{}", format!("Updated {} dependency nodes", lockfile.dependencies.len()).green());
            for (node_id, package) in &lockfile.dependencies {
                let source = match &package.source {
                    crate::package::LockedSource::Path { path } => format!("path: {}", path),
                    crate::package::LockedSource::Git { url, revision } => format!("git: {}#{}", url, revision),
                    crate::package::LockedSource::Registry { registry, namespace, version, .. } => {
                        format!("registry: {}/{}@{}", registry, namespace, version)
                    }
                };
                println!("  {} {} v{} ({})", node_id, package.name, package.version, source);
            }
        }

        Ok(())
    }

    fn lock(args: PackageLockArgs) -> Result<()> {
        refresh_lockfile_from_manifest(std::path::Path::new("."))?;
        let lockfile = Lockfile::read_from_root(std::path::Path::new("."))?.expect("lockfile was just written");
        CommandOutcome {
            machine: serde_json::json!({
                "status": "ok",
                "lockfile": "Cell.lock",
                "schema": lockfile.schema,
                "dependency_nodes": lockfile.dependencies.len(),
                "environments": lockfile.environments.keys().collect::<Vec<_>>(),
            }),
            human_lines: vec![
                "Dependency graph locked".green().to_string(),
                format!("  {} dependency node(s)", lockfile.dependencies.len()),
            ],
        }
        .emit(args.json)
    }

    fn info(args: InfoArgs) -> Result<()> {
        let pm = PackageManager::new(".");
        let manifest = pm.read_manifest()?;
        let mut human_lines = vec![
            "Package Info:".bold().to_string(),
            format!("  Name:        {}", manifest.package.name),
            format!("  Version:     {}", manifest.package.version),
            format!("  Description: {}", manifest.package.description),
            format!("  License:     {}", manifest.package.license),
            format!("  Authors:     {}", manifest.package.authors.join(", ")),
            format!("  Entry:       {}", manifest.package.entry),
            "  Dependencies:".to_string(),
        ];
        human_lines.extend(manifest.dependencies.iter().map(|(name, dep)| format!("    - {}: {:?}", name, dep)));
        CommandOutcome {
            machine: serde_json::json!({
                "status": "ok",
                "manifest": "Cell.toml",
                "package": manifest.package,
                "dependencies": manifest.dependencies,
                "dev_dependencies": manifest.dev_dependencies,
                "features": manifest.features,
                "environments": manifest.environments,
                "dependency_overrides": manifest.dependency_overrides,
                "resolvers": manifest.resolvers,
                "build": manifest.build,
                "policy": manifest.policy,
                "deploy": manifest.deploy,
                "metadata": manifest.metadata,
            }),
            human_lines,
        }
        .emit(args.json)
    }

    fn login(args: LoginArgs) -> Result<()> {
        Self::auth_capability(AuthCapabilityArgs { registry_origin: args.registry, ..Default::default() })
    }

    fn auth_capability(args: AuthCapabilityArgs) -> Result<()> {
        let registry_origin = args
            .registry_origin
            .or_else(|| std::env::var("CELLSCRIPT_REGISTRY_ORIGIN").ok())
            .unwrap_or_else(|| crate::package::registry::DEFAULT_PUBLIC_REGISTRY_ORIGIN.to_string());
        let principal_type =
            args.principal_type.or_else(|| std::env::var("CELLSCRIPT_PRINCIPAL_TYPE").ok()).unwrap_or_else(|| "joyid_ckb".to_string());
        if principal_type != "joyid_ckb" && principal_type != "ckb_secp256k1" {
            return Err(crate::error::CompileError::without_span("principal type must be joyid_ckb or ckb_secp256k1"));
        }
        let principal_id = args.principal_id.or_else(|| std::env::var("CELLSCRIPT_PRINCIPAL_ID").ok()).ok_or_else(|| {
            crate::error::CompileError::without_span(
                "principal id is required; pass --principal-id or set CELLSCRIPT_PRINCIPAL_ID to the normalized wallet identity binding",
            )
        })?;
        let explicit_capability_pubkey = args.capability_pubkey.or_else(|| std::env::var("CELLSCRIPT_CAPABILITY_PUBKEY").ok());
        let (capability_pubkey, generated_key_id) = match explicit_capability_pubkey {
            Some(capability_pubkey) => (capability_pubkey, None),
            None => {
                let generated = generate_and_store_registry_capability_key()?;
                (generated.capability_pubkey, Some(generated.key_id))
            }
        };
        let capability_key_id = registry_capability_key_id(&capability_pubkey);
        let requested_scopes = resolve_requested_scopes(args.scopes)?;
        let issued_at = current_utc_timestamp();
        let expires_at = utc_timestamp_after_seconds(10 * 60);
        let capability_expires_at = resolve_capability_expires_at(args.capability_expires_at, args.expires)?;
        let nonce =
            registry_auth_nonce(&registry_origin, &principal_type, &principal_id, &capability_pubkey, &requested_scopes, &issued_at);
        let payload = crate::package::registry::CapabilityAuthorisationPayload::new(
            registry_origin,
            principal_type,
            principal_id,
            capability_pubkey,
            requested_scopes,
            capability_expires_at,
            nonce,
            issued_at,
            expires_at,
            crate::VERSION.to_string(),
        );
        let machine = serde_json::to_value(&payload)?;
        let mut human_lines = vec![
            "Capability authorisation payload".green().to_string(),
            format!("  Protocol: {}", payload.protocol),
            format!("  Action: {}", payload.action),
            format!("  Registry: {}", payload.registry_origin),
            format!("  Principal: {}:{}", payload.principal_type, payload.principal_id),
            format!("  Capability pubkey: {}", payload.capability_pubkey),
            format!("  Capability key id: {}", capability_key_id),
        ];
        if generated_key_id.is_some() {
            human_lines.push("  Capability private key: stored in the OS keychain".to_string());
        }
        human_lines.extend([
            format!("  Scopes: {}", payload.requested_scopes.join(", ")),
            format!("  Capability expires: {}", payload.capability_expires_at),
            String::new(),
            "Sign this payload with the matching JoyID or CKB wallet, then submit the signed authorisation to the registry write API:"
                .to_string(),
            serde_json::to_string_pretty(&payload)?,
        ]);
        CommandOutcome { machine, human_lines }.emit(args.json)
    }

    fn auth_reproducer_create(args: AuthReproducerCreateArgs) -> Result<()> {
        let builder_id = args.builder_id.trim().to_string();
        if builder_id.is_empty() || builder_id.len() > 200 {
            return Err(crate::error::CompileError::without_span("builder id must contain 1 to 200 characters"));
        }
        let trust_domain = args.trust_domain.trim().to_string();
        if trust_domain.is_empty() || trust_domain.len() > 200 {
            return Err(crate::error::CompileError::without_span("trust domain must contain 1 to 200 characters"));
        }

        let generated = generate_registry_key_material()?;
        let (private_key_storage, storage_line) = if let Some(path) = args.private_key_output {
            write_new_reproducer_private_key(&path, &generated.private_key_pkcs8)?;
            let path_display = path.display().to_string();
            (
                serde_json::json!({
                    "kind": "pkcs8_base64_file",
                    "path": &path_display,
                    "environment_variable": "CELLSCRIPT_REPRODUCER_PRIVATE_KEY_PKCS8_B64",
                }),
                format!("  Private key: restricted PKCS#8 base64 file at {path_display}"),
            )
        } else {
            store_registry_private_key(&generated.key_id, &generated.private_key_pkcs8)?;
            (
                serde_json::json!({
                    "kind": "os_keychain",
                    "service": "cellscript-registry",
                    "key_id": &generated.key_id,
                }),
                "  Private key: stored in the OS keychain".to_string(),
            )
        };
        let machine = serde_json::json!({
            "schema": "cellscript-reproducer-builder-enrollment-v1",
            "builder_id": &builder_id,
            "trust_domain": &trust_domain,
            "builder_key_id": &generated.key_id,
            "builder_public_key": &generated.public_key,
            "policy_builder": {
                "builder_id": &builder_id,
                "trust_domain": &trust_domain,
                "public_key": &generated.public_key,
            },
            "private_key_storage": private_key_storage,
        });
        let human_lines = vec![
            "Reproducer builder key created".green().to_string(),
            format!("  Builder: {builder_id}"),
            format!("  Trust domain: {trust_domain}"),
            format!("  Builder key id: {}", generated.key_id),
            format!("  Builder public key: {}", generated.public_key),
            storage_line,
            String::new(),
            "Send only policy_builder to the Registry operator. Keep the private key inside this builder's independent custody."
                .to_string(),
        ];
        CommandOutcome { machine, human_lines }.emit(args.json)
    }

    fn auth_capability_submit(args: AuthCapabilitySubmitArgs) -> Result<()> {
        let api_base = resolve_registry_api_base(args.api_url)?;
        let registry_origin = registry_origin_from_api_base(&api_base)?;
        let payload = read_capability_authorisation_payload(&args.payload)?;
        if payload.registry_origin != registry_origin {
            return Err(crate::error::CompileError::without_span(format!(
                "capability payload registry_origin '{}' does not match API origin '{}'",
                payload.registry_origin, registry_origin
            )));
        }
        let wallet_signature = read_json_value(&args.wallet_signature)?;
        let body = serde_json::json!({
            "payload": payload,
            "wallet_signature": wallet_signature,
        });
        let endpoint = format!("{}/v1/capabilities", api_base.trim_end_matches('/'));
        let response = submit_registry_json_request(&endpoint, &body, "Submitted capability authorisation", args.json)?;
        if !args.json {
            if let Some(key_id) = response.get("key_id").and_then(serde_json::Value::as_str) {
                println!("  Capability key id: {}", key_id);
            }
            if let Some(status) = response.get("status").and_then(serde_json::Value::as_str) {
                println!("  Status: {}", status);
            }
        }
        Ok(())
    }

    fn auth_namespace_claim(args: AuthNamespaceClaimArgs) -> Result<()> {
        let api_base = resolve_registry_api_base(args.api_url)?;
        let registry_origin = registry_origin_from_api_base(&api_base)?;
        let namespace = args.namespace.trim();
        if namespace.is_empty() {
            return Err(crate::error::CompileError::without_span("namespace is required for registry namespace claim"));
        }
        let payload = read_capability_authorisation_payload(&args.payload)?;
        if payload.registry_origin != registry_origin {
            return Err(crate::error::CompileError::without_span(format!(
                "namespace claim payload registry_origin '{}' does not match API origin '{}'",
                payload.registry_origin, registry_origin
            )));
        }
        let namespace_scope_prefix = format!("publish:{namespace}/");
        if !payload.requested_scopes.iter().any(|scope| scope.starts_with(&namespace_scope_prefix)) {
            return Err(crate::error::CompileError::without_span(format!(
                "namespace claim payload has no publish scope for namespace '{namespace}'"
            )));
        }
        let wallet_signature = read_json_value(&args.wallet_signature)?;
        let body = serde_json::json!({
            "namespace": namespace,
            "payload": payload,
            "wallet_signature": wallet_signature,
        });
        let endpoint = format!("{}/v1/namespaces/claim", api_base.trim_end_matches('/'));
        let response = submit_registry_json_request(&endpoint, &body, "Claimed registry namespace", args.json)?;
        if !args.json
            && let Some(status) = response.get("status").and_then(serde_json::Value::as_str)
        {
            println!("  Namespace: {namespace}");
            println!("  Status: {status}");
            if status != "active" {
                println!("  Publishing remains blocked until registry review activates the namespace.");
            }
        }
        Ok(())
    }

    fn auth_capability_revoke(args: AuthCapabilityRevokeArgs) -> Result<()> {
        if args.payload.is_none() && args.wallet_signature.is_some() {
            return Err(crate::error::CompileError::without_span(
                "capability revocation with --wallet-signature must use --payload from a previously generated revoke challenge",
            ));
        }

        let payload = if let Some(payload_path) = args.payload.as_deref() {
            read_capability_revocation_payload(payload_path)?
        } else {
            let registry_origin = args
                .registry_origin
                .or_else(|| std::env::var("CELLSCRIPT_REGISTRY_ORIGIN").ok())
                .unwrap_or_else(|| crate::package::registry::DEFAULT_PUBLIC_REGISTRY_ORIGIN.to_string());
            let principal_type = args
                .principal_type
                .or_else(|| std::env::var("CELLSCRIPT_PRINCIPAL_TYPE").ok())
                .unwrap_or_else(|| "joyid_ckb".to_string());
            if principal_type != "joyid_ckb" && principal_type != "ckb_secp256k1" {
                return Err(crate::error::CompileError::without_span("principal type must be joyid_ckb or ckb_secp256k1"));
            }
            let principal_id = args.principal_id.or_else(|| std::env::var("CELLSCRIPT_PRINCIPAL_ID").ok()).ok_or_else(|| {
                crate::error::CompileError::without_span(
                    "principal id is required for capability revoke; pass --principal-id or set CELLSCRIPT_PRINCIPAL_ID to the normalized wallet identity binding",
                )
            })?;
            let capability_key_id =
                args.capability_key_id.or_else(|| std::env::var("CELLSCRIPT_CAPABILITY_KEY_ID").ok()).ok_or_else(|| {
                    crate::error::CompileError::without_span(
                        "capability key id is required for capability revoke; pass --capability-key-id or set CELLSCRIPT_CAPABILITY_KEY_ID",
                    )
                })?;
            let issued_at = current_utc_timestamp();
            let expires_at = utc_timestamp_after_seconds(10 * 60);
            let nonce = registry_revoke_nonce(&registry_origin, &principal_type, &principal_id, &capability_key_id, &issued_at);
            crate::package::registry::CapabilityRevocationPayload::new(
                registry_origin,
                principal_type,
                principal_id,
                capability_key_id,
                nonce,
                issued_at,
                expires_at,
                crate::VERSION.to_string(),
            )
        };

        let Some(signature_path) = args.wallet_signature.as_deref() else {
            if args.json {
                print_json(&serde_json::to_value(&payload)?)?;
            } else {
                println!("{}", "Capability revocation payload".green());
                println!("  Protocol: {}", payload.protocol);
                println!("  Action: {}", payload.action);
                println!("  Registry: {}", payload.registry_origin);
                println!("  Principal: {}:{}", payload.principal_type, payload.principal_id);
                println!("  Capability key id: {}", payload.capability_key_id);
                println!();
                println!("Sign this payload with the matching JoyID or CKB wallet, then submit it with:");
                println!("  cellc auth capability revoke --payload <payload.json> --wallet-signature <wallet-signature.json>");
                println!("{}", serde_json::to_string_pretty(&payload)?);
            }
            return Ok(());
        };

        let api_base = resolve_registry_api_base(args.api_url)?;
        let registry_origin = registry_origin_from_api_base(&api_base)?;
        if payload.registry_origin != registry_origin {
            return Err(crate::error::CompileError::without_span(format!(
                "capability revocation registry_origin '{}' does not match API origin '{}'",
                payload.registry_origin, registry_origin
            )));
        }
        let wallet_signature = read_json_value(signature_path)?;
        let mut body = serde_json::json!({
            "payload": payload,
            "wallet_signature": wallet_signature,
        });
        if let Some(reason) = args.reason.filter(|reason| !reason.trim().is_empty()) {
            body["reason"] = serde_json::Value::String(reason);
        }
        let endpoint = format!(
            "{}/v1/capabilities/{}/revoke",
            api_base.trim_end_matches('/'),
            body["payload"]["capability_key_id"].as_str().unwrap_or_default()
        );
        let response = submit_registry_json_request(&endpoint, &body, "Revoked capability", args.json)?;
        if !args.json {
            if let Some(key_id) = response.get("key_id").and_then(serde_json::Value::as_str) {
                println!("  Capability key id: {}", key_id);
            }
            if let Some(revoked_at) = response.get("revoked_at").and_then(serde_json::Value::as_str) {
                println!("  Revoked at: {}", revoked_at);
            }
        }
        Ok(())
    }

    fn registry_verify(args: RegistryVerifyArgs) -> Result<()> {
        let root = std::path::Path::new(".");

        // Read Cell.lock
        let lockfile = Lockfile::read_from_root(root)?
            .ok_or_else(|| crate::error::CompileError::without_span("Cell.lock not found; run 'cellc build' first"))?;

        // Read Deployed.toml
        let deployed = crate::package::DeployedManifest::read_from_root(root)?
            .ok_or_else(|| crate::error::CompileError::without_span("Deployed.toml not found; deploy the contract first"))?;

        let mut violations = Vec::new();

        if lockfile.package.name != deployed.package.name {
            violations.push(format!(
                "package name mismatch: Cell.lock has '{}', Deployed.toml has '{}'",
                lockfile.package.name, deployed.package.name
            ));
        }
        if lockfile.package.version != deployed.package.version {
            violations.push(format!(
                "package version mismatch: Cell.lock has '{}', Deployed.toml has '{}'",
                lockfile.package.version, deployed.package.version
            ));
        }
        if lockfile.package.edition != deployed.package.edition {
            violations.push(format!(
                "package edition mismatch: Cell.lock has '{}', Deployed.toml has '{}'",
                lockfile.package.edition, deployed.package.edition
            ));
        }
        if let (Some(lock_hash), Some(deployed_hash)) = (&lockfile.package.source_hash, &deployed.package.source_hash) {
            if lock_hash != deployed_hash {
                violations.push(format!("source_hash mismatch: Cell.lock has '{}', Deployed.toml has '{}'", lock_hash, deployed_hash));
            }
        } else {
            violations.push("source_hash must be present in both Cell.lock and Deployed.toml".to_string());
        }

        match &lockfile.package_build {
            Some(build) => push_missing_locked_build_identity("Cell.lock [package.build]", build, &mut violations),
            None => violations.push("Cell.lock has no [package.build]".to_string()),
        }
        match &deployed.build {
            Some(build) => push_missing_deployed_build_identity("Deployed.toml [build]", build, &mut violations),
            None => violations.push("Deployed.toml has no [build]".to_string()),
        }

        if let (Some(build), Some(deployed_build)) = (&lockfile.package_build, &deployed.build) {
            if build.edition != deployed_build.edition {
                violations.push(format!(
                    "build edition mismatch: Cell.lock has '{}', Deployed.toml has '{}'",
                    build.edition, deployed_build.edition
                ));
            }
            if build.compatibility_profile_hash != deployed_build.compatibility_profile_hash {
                violations.push(format!(
                    "compatibility_profile_hash mismatch: Cell.lock has '{}', Deployed.toml has '{}'",
                    build.compatibility_profile_hash, deployed_build.compatibility_profile_hash
                ));
            }
            compare_optional_build_field(
                "compiler_version",
                &build.compiler_version,
                &deployed_build.compiler_version,
                &mut violations,
            );
            compare_optional_build_field("artifact_hash", &build.artifact_hash, &deployed_build.artifact_hash, &mut violations);
            compare_optional_build_field("metadata_hash", &build.metadata_hash, &deployed_build.metadata_hash, &mut violations);
            compare_optional_build_field("schema_hash", &build.schema_hash, &deployed_build.schema_hash, &mut violations);
            compare_optional_build_field(
                "cell_data_codec_manifest_hash",
                &build.cell_data_codec_manifest_hash,
                &deployed_build.cell_data_codec_manifest_hash,
                &mut violations,
            );
            compare_optional_build_field("abi_hash", &build.abi_hash, &deployed_build.abi_hash, &mut violations);
            compare_optional_build_field(
                "constraints_hash",
                &build.constraints_hash,
                &deployed_build.constraints_hash,
                &mut violations,
            );
        }

        // Check deployment records
        let mut seen_networks = BTreeSet::new();
        for deployment in &deployed.deployments {
            seen_networks.insert(deployment.network.clone());
            push_deployment_status_violation(deployment, &mut violations);

            let Some(deployment_ref) = lockfile.deployment.get(&deployment.network) else {
                violations.push(format!("deployment for network '{}' is missing from Cell.lock", deployment.network));
                continue;
            };

            if deployment_ref.record.is_empty() {
                violations.push(format!("deployment ref for network '{}' has empty record", deployment.network));
            } else {
                let chain_record = format!("{}:{}", deployment.chain_id, deployment.out_point);
                let network_record = format!("{}:{}", deployment.network, deployment.out_point);
                if deployment_ref.record != deployment.out_point
                    && deployment_ref.record != chain_record
                    && deployment_ref.record != network_record
                {
                    violations.push(format!(
                        "deployment record mismatch for network '{}': Cell.lock has '{}', Deployed.toml out_point is '{}'",
                        deployment.network, deployment_ref.record, deployment.out_point
                    ));
                }
            }

            match &deployment_ref.code_hash {
                Some(code_hash) if code_hash == &deployment.code_hash => {}
                Some(code_hash) => violations.push(format!(
                    "code_hash mismatch for network '{}': Cell.lock has '{}', Deployed.toml has '{}'",
                    deployment.network, code_hash, deployment.code_hash
                )),
                None => violations.push(format!("deployment ref for network '{}' has no code_hash", deployment.network)),
            }
            match &deployment_ref.out_point {
                Some(out_point) if out_point == &deployment.out_point => {}
                Some(out_point) => violations.push(format!(
                    "out_point mismatch for network '{}': Cell.lock has '{}', Deployed.toml has '{}'",
                    deployment.network, out_point, deployment.out_point
                )),
                None => violations.push(format!("deployment ref for network '{}' has no out_point", deployment.network)),
            }
            match &deployment_ref.data_hash {
                Some(data_hash) if data_hash == &deployment.data_hash => {}
                Some(data_hash) => violations.push(format!(
                    "data_hash mismatch for network '{}': Cell.lock has '{}', Deployed.toml has '{}'",
                    deployment.network, data_hash, deployment.data_hash
                )),
                None => violations.push(format!("deployment ref for network '{}' has no data_hash", deployment.network)),
            }
            if let Some(record_hash) = &deployment_ref.record_hash {
                let computed = hash_json_value("deployment record", deployment)?;
                if record_hash != &computed {
                    violations.push(format!(
                        "record_hash mismatch for network '{}': Cell.lock has '{}', computed '{}'",
                        deployment.network, record_hash, computed
                    ));
                }
            }

            // TYPE_ID upgrade lineage (Phase 2, off-chain consistency): when a
            // deployment declares `upgrade_lineage`, it must not point at itself
            // and must not be empty. We do not require it to match a record kept
            // in Deployed.toml, because historical deployments are often pruned;
            // on-chain TYPE_ID upgrade-chain verification remains a live-RPC
            // concern. This off-chain check catches the common copy-paste error
            // where a lineage field accidentally names the current deployment.
            if let Some(lineage) = &deployment.upgrade_lineage {
                if lineage.trim().is_empty() {
                    violations.push(format!(
                        "upgrade_lineage for network '{}' is empty; remove the field or point it at a prior out_point",
                        deployment.network
                    ));
                } else if lineage.trim() == deployment.out_point {
                    violations.push(format!(
                        "upgrade_lineage for network '{}' points at the deployment's own out_point '{}'; lineage must reference a prior deployment",
                        deployment.network, deployment.out_point
                    ));
                }
            }
        }
        for network in lockfile.deployment.keys() {
            if !seen_networks.contains(network) {
                violations.push(format!("Cell.lock has stale deployment ref for network '{}'", network));
            }
        }
        let trust_report =
            verify_registry_trust_metadata(&deployed, args.require_publisher_signature, args.require_audit_report, &mut violations);
        let live_report = if args.live {
            let rpc_url = args.rpc_url.clone().or_else(|| std::env::var(CELLSCRIPT_CKB_RPC_URL_ENV).ok()).ok_or_else(|| {
                crate::error::CompileError::without_span(format!(
                    "registry verify --live requires --rpc-url or {}",
                    CELLSCRIPT_CKB_RPC_URL_ENV
                ))
            })?;
            Some(verify_live_deployments(&deployed, &rpc_url, args.network.as_deref(), &mut violations)?)
        } else {
            None
        };

        let passed = violations.is_empty();
        let outcome = CommandOutcome {
            machine: serde_json::json!({
                "status": if passed { "ok" } else { "failed" },
                "trust": trust_report,
                "live": live_report.unwrap_or_else(|| serde_json::json!({
                    "enabled": false,
                    "evidence": []
                })),
                "violations": violations,
            }),
            human_lines: if passed {
                vec!["Registry verification passed".green().to_string()]
            } else {
                let mut lines = vec!["Registry verification failed".red().to_string()];
                lines.extend(violations.iter().map(|violation| format!("  - {}", violation)));
                lines
            },
        };
        if passed {
            outcome.emit(args.json)
        } else {
            Err(outcome.failure(format!("registry verification failed:\n  - {}", violations.join("\n  - "))))
        }
    }

    fn package_verify(args: PackageVerifyArgs) -> Result<()> {
        let root = std::path::Path::new(".");
        let pm = PackageManager::new(root);
        let manifest = pm.read_manifest()?;

        // Read Cell.lock
        let lockfile = Lockfile::read_from_root(root)?
            .ok_or_else(|| crate::error::CompileError::without_span("Cell.lock not found; run 'cellc build' first"))?;

        let mut violations = Vec::new();

        if lockfile.package.name != manifest.package.name {
            violations.push(format!(
                "package name mismatch: Cell.toml has '{}', Cell.lock has '{}'",
                manifest.package.name, lockfile.package.name
            ));
        }
        if lockfile.package.version != manifest.package.version {
            violations.push(format!(
                "package version mismatch: Cell.toml has '{}', Cell.lock has '{}'",
                manifest.package.version, lockfile.package.version
            ));
        }
        if lockfile.package.edition != manifest.package.edition {
            violations.push(format!(
                "package edition mismatch: Cell.toml has '{}', Cell.lock has '{}'",
                manifest.package.edition, lockfile.package.edition
            ));
        }
        if lockfile.package.namespace != manifest.package.namespace {
            violations.push(format!(
                "package namespace mismatch: Cell.toml has '{:?}', Cell.lock has '{:?}'",
                manifest.package.namespace, lockfile.package.namespace
            ));
        }

        match &lockfile.package.source_hash {
            Some(source_hash) => {
                let computed = crate::package::registry::compute_source_hash(root)?;
                if &computed != source_hash {
                    violations.push(format!("source_hash mismatch: Cell.lock has '{}', computed '{}'", source_hash, computed));
                }
            }
            None => violations.push("Cell.lock [package] has no source_hash; run 'cellc build' to populate".to_string()),
        }

        match &lockfile.package_build {
            Some(build) => push_missing_locked_build_identity("Cell.lock [package.build]", build, &mut violations),
            None => violations.push("Cell.lock has no [package.build]; run 'cellc build' to populate build identity".to_string()),
        }

        let computed_manifest_digest = crate::package::compute_manifest_digest(root)?;
        if lockfile.root.manifest_digest != computed_manifest_digest {
            violations.push(format!(
                "manifest digest mismatch: Cell.lock has '{}', computed '{}'",
                lockfile.root.manifest_digest, computed_manifest_digest
            ));
        }
        for issue in lockfile.consistency_issues(&manifest) {
            violations.push(issue);
        }
        let mut verification_modes = Vec::new();
        if manifest.dependency_overrides.is_empty() {
            verification_modes.push(None);
        }
        verification_modes.extend(manifest.environments.keys().cloned().map(Some));
        let mut resolved = BTreeMap::new();
        for environment in verification_modes {
            let options = crate::package::ResolutionOptions {
                scope: crate::package::DependencyScope::Test,
                all_features: true,
                environment,
                ..crate::package::ResolutionOptions::default()
            };
            let mut mode_manager = PackageManager::new(root);
            match mode_manager.resolve_locked_dependencies(&options) {
                Ok(()) => resolved.extend(mode_manager.get_resolved().clone()),
                Err(error) => violations.push(format!("locked dependency materialization failed: {}", error)),
            }
        }
        for issue in lockfile.consistency_issues_with_resolved(&manifest, &resolved) {
            if !violations.contains(&issue) {
                violations.push(issue);
            }
        }
        for (name, locked) in &lockfile.dependencies {
            if matches!(locked.source, crate::package::LockedSource::Registry { .. }) && locked.source_hash.is_none() {
                violations.push(format!("registry dependency '{}' has no source_hash in Cell.lock", name));
            }
        }

        let passed = violations.is_empty();
        let outcome = CommandOutcome {
            machine: serde_json::json!({
                "status": if passed { "ok" } else { "failed" },
                "violations": violations,
            }),
            human_lines: if passed {
                vec!["Package verification passed".green().to_string()]
            } else {
                let mut lines = vec!["Package verification failed".red().to_string()];
                lines.extend(violations.iter().map(|violation| format!("  - {}", violation)));
                lines
            },
        };
        if passed {
            outcome.emit(args.json)
        } else {
            Err(outcome.failure(format!("package verification failed:\n  - {}", violations.join("\n  - "))))
        }
    }

    fn registry_add(args: RegistryAddArgs) -> Result<()> {
        let root = std::path::Path::new(".");
        let cache_dir = root.join(".cell/registry-cache");
        let registry_url = crate::package::registry::default_registry_url();
        let discovery = crate::package::registry::DiscoveryIndex::new(&registry_url, &cache_dir);

        let entry_path = discovery.add_entry(&args.namespace, &args.name, &args.source)?;
        let discovery_clone = entry_path.parent().and_then(|path| path.parent()).unwrap_or(cache_dir.as_path());
        let entry_rel = entry_path.strip_prefix(discovery_clone).unwrap_or(entry_path.as_path());

        println!("{}", "Registry entry added".green());
        println!("  Namespace: {}", args.namespace);
        println!("  Name: {}", args.name);
        println!("  Source: {}", args.source);
        println!();
        println!("  Next steps:");
        println!("    cd {} && git add {}", discovery_clone.display(), entry_rel.display());
        println!("    git commit -m \"add {}/{}\"", args.namespace, args.name);
        println!("    Open a PR to the cellscript-registry repository");

        Ok(())
    }

    fn registry_edit(args: RegistryEditArgs) -> Result<()> {
        let version =
            args.yank.ok_or_else(|| crate::error::CompileError::without_span("registry edit currently requires --yank <VERSION>"))?;
        let root = std::path::Path::new(".");
        let mut index = crate::package::registry::RegistryIndex::read_from_repo(root)?;
        let Some(entry) = index.versions.iter_mut().find(|entry| entry.version == version) else {
            return Err(crate::error::CompileError::without_span(format!(
                "registry.json has no version '{}' for {}/{}",
                version, index.namespace, index.name
            )));
        };

        entry.yanked = true;
        entry.yanked_at = Some(args.yanked_at.unwrap_or_else(current_utc_timestamp));
        entry.yanked_reason = args.reason;
        entry.replaced_by = args.replaced_by;
        let reason = entry.yanked_reason.clone();
        let replaced_by = entry.replaced_by.clone();
        index.write_to_repo(root)?;

        println!("{}", "Registry version yanked".green());
        println!("  Package: {}/{}", index.namespace, index.name);
        println!("  Version: {}", version);
        if let Some(reason) = reason.as_deref() {
            println!("  Reason: {}", reason);
        }
        if let Some(replacement) = replaced_by.as_deref() {
            println!("  Replaced by: {}", replacement);
        }
        println!();
        println!("  Next steps:");
        println!("    git add registry.json");
        println!("    git commit -m \"yank {}/{}@{}\"", index.namespace, index.name, version);
        println!("    Open a PR with the advisory or replacement evidence");

        Ok(())
    }

    fn certify(args: CertifyArgs) -> Result<()> {
        if args.plugin != NOVASEAL_CERTIFICATION_PLUGIN {
            return Err(crate::error::CompileError::without_span(format!(
                "unknown certification plugin '{}'; available plugins: {}",
                args.plugin, NOVASEAL_CERTIFICATION_PLUGIN
            )));
        }

        let repo_root = args.repo_root.unwrap_or(std::env::current_dir()?);
        let report_provided = args.report.is_some();
        let plugin_report_path = args.report.clone().unwrap_or_else(|| repo_root.join("target/novaseal-production-gates.json"));
        let report_generated = !report_provided;

        let plugin_report = if report_provided {
            read_json_value(&plugin_report_path)?
        } else {
            let report = super::novaseal_certification::build_report(&repo_root)?;
            if let Some(parent) = plugin_report_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(
                &plugin_report_path,
                serde_json::to_string_pretty(&report).map_err(|error| {
                    crate::error::CompileError::without_span(format!("failed to serialize NovaSeal production-gate report: {}", error))
                })?,
            )?;
            report
        };

        let implementation_path = repo_root.join("src/cli/novaseal_certification.rs");
        let summary = novaseal_certification_summary(
            &plugin_report,
            &repo_root,
            &plugin_report_path,
            &implementation_path,
            report_generated,
            args.require_production,
        )?;
        let output_path = args.output.unwrap_or_else(|| repo_root.join("target/cellscript-certification/novaseal-profile-v0.json"));
        if let Some(parent) = output_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(
            &output_path,
            serde_json::to_string_pretty(&summary).map_err(|error| {
                crate::error::CompileError::without_span(format!("failed to serialize certification report: {}", error))
            })?,
        )?;

        let passed = summary["status"].as_str() == Some("passed");
        let failure_message = (!passed).then(|| novaseal_certification_failure_message(&summary));
        let outcome = CommandOutcome {
            human_lines: vec![
                "Certification report generated".to_string(),
                format!("  Plugin: {}", args.plugin),
                format!("  Status: {}", summary["status"].as_str().unwrap_or("unknown")),
                format!("  Level: {}", summary["certification_level"].as_str().unwrap_or("unknown")),
                format!("  Output: {}", output_path.display()),
                format!("  Plugin report: {}", plugin_report_path.display()),
            ],
            machine: summary,
        };
        if passed {
            outcome.emit(args.json)
        } else {
            Err(outcome.failure(failure_message.unwrap_or_else(|| "certification failed".to_string())))
        }
    }
}

#[cfg(feature = "vm-runner")]
type CliVmMachine = TraceMachine<DefaultCoreMachine<u64, WXorXMemory<SparseMemory<u64>>>>;

/// Convert days since Unix epoch (1970-01-01) to (year, month, day).
/// Implements the civil date algorithm from Howard Hinnant.
fn civil_date_from_days(z: i32) -> (i32, u32, u32) {
    let z = z + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let y = y + if m <= 2 { 1 } else { 0 };
    (y, m as u32, d as u32)
}

pub(super) fn current_utc_timestamp() -> String {
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    utc_timestamp_from_unix_secs(secs)
}

pub(super) fn utc_timestamp_after_seconds(delta_secs: u64) -> String {
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    utc_timestamp_from_unix_secs(secs.saturating_add(delta_secs))
}

fn utc_timestamp_from_unix_secs(secs: u64) -> String {
    let days_since_epoch = secs / 86400;
    let time_of_day = secs % 86400;
    let (year, month, day) = civil_date_from_days(days_since_epoch as i32);
    let hour = (time_of_day / 3600) as u8;
    let minute = ((time_of_day % 3600) / 60) as u8;
    let second = (time_of_day % 60) as u8;
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", year, month, day, hour, minute, second)
}

fn resolve_requested_scopes(mut scopes: Vec<String>) -> Result<Vec<String>> {
    if scopes.iter().any(|scope| scope.trim().is_empty()) {
        return Err(invalid_capability_scope(""));
    }
    scopes = scopes.into_iter().map(|scope| scope.trim().to_string()).collect();
    if !scopes.is_empty() {
        validate_capability_scopes(&scopes)?;
        return Ok(scopes);
    }

    let manifest = PackageManager::new(".").read_manifest().map_err(|_| {
        crate::error::CompileError::without_span(
            "at least one capability scope is required outside a package directory; pass --scope <publish|deployment|availability>:<namespace>/<package>",
        )
    })?;
    let namespace = manifest.package.namespace.ok_or_else(|| {
        crate::error::CompileError::without_span(
            "cannot infer the publish capability scope because [package].namespace is missing; pass --scope publish:<namespace>/<package>",
        )
    })?;
    if manifest.package.name.is_empty() {
        return Err(crate::error::CompileError::without_span(
            "cannot infer the publish capability scope because [package].name is empty; pass --scope publish:<namespace>/<package>",
        ));
    }

    let coordinate = format!("{}/{}", namespace, manifest.package.name);
    Ok(vec![format!("publish:{coordinate}")])
}

fn validate_capability_scopes(scopes: &[String]) -> Result<()> {
    let mut seen = BTreeSet::new();
    for scope in scopes {
        if !seen.insert(scope.as_str()) {
            return Err(crate::error::CompileError::without_span(format!("duplicate capability scope '{scope}'"))
                .with_category(crate::error::CompileErrorCategory::Usage));
        }
        let Some((action, coordinate)) = scope.split_once(':') else {
            return Err(invalid_capability_scope(scope));
        };
        if !matches!(action, "publish" | "deployment" | "availability") {
            return Err(invalid_capability_scope(scope));
        }
        let Some((namespace, name)) = coordinate.split_once('/') else {
            return Err(invalid_capability_scope(scope));
        };
        validate_declared_artifact_ident(namespace, "capability scope namespace").map_err(|_| invalid_capability_scope(scope))?;
        if name != "*" {
            validate_declared_artifact_ident(name, "capability scope package").map_err(|_| invalid_capability_scope(scope))?;
        }
    }
    Ok(())
}

fn invalid_capability_scope(scope: &str) -> CompileError {
    crate::error::CompileError::without_span(format!(
        "invalid capability scope '{scope}'; expected <publish|deployment|availability>:<namespace>/<package-or-*>",
    ))
    .with_category(crate::error::CompileErrorCategory::Usage)
}

fn resolve_capability_expires_at(explicit_timestamp: Option<String>, relative: Option<String>) -> Result<String> {
    if let Some(timestamp) = explicit_timestamp {
        return Ok(timestamp);
    }

    let Some(relative) = relative else {
        return Ok(utc_timestamp_after_seconds(90 * 24 * 60 * 60));
    };
    let trimmed = relative.trim();
    if let Some(days) = trimmed.strip_suffix('d') {
        let days: u64 = days.parse().map_err(|_| {
            crate::error::CompileError::without_span(format!("invalid --expires value '{}'; expected a duration like 90d", relative))
                .with_category(crate::error::CompileErrorCategory::Usage)
        })?;
        return Ok(utc_timestamp_after_seconds(days.saturating_mul(24 * 60 * 60)));
    }
    if let Some(hours) = trimmed.strip_suffix('h') {
        let hours: u64 = hours.parse().map_err(|_| {
            crate::error::CompileError::without_span(format!(
                "invalid --expires value '{}'; expected a duration like 90d or 24h",
                relative
            ))
            .with_category(crate::error::CompileErrorCategory::Usage)
        })?;
        return Ok(utc_timestamp_after_seconds(hours.saturating_mul(60 * 60)));
    }
    if trimmed.contains('T') && trimmed.ends_with('Z') {
        return Ok(trimmed.to_string());
    }

    Err(crate::error::CompileError::without_span(format!(
        "invalid --expires value '{}'; expected a duration like 90d/24h or an absolute UTC timestamp",
        relative
    ))
    .with_category(crate::error::CompileErrorCategory::Usage))
}

fn registry_auth_nonce(
    registry_origin: &str,
    principal_type: &str,
    principal_id: &str,
    capability_pubkey: &str,
    requested_scopes: &[String],
    issued_at: &str,
) -> String {
    let material = format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}",
        crate::package::registry::REGISTRY_AUTH_PROTOCOL,
        registry_origin,
        principal_type,
        principal_id,
        capability_pubkey,
        requested_scopes.join(","),
        issued_at
    );
    format!("0x{}", hex::encode(crate::ckb_blake2b256(material.as_bytes())))
}

fn registry_revoke_nonce(
    registry_origin: &str,
    principal_type: &str,
    principal_id: &str,
    capability_key_id: &str,
    issued_at: &str,
) -> String {
    let material = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        crate::package::registry::REVOKE_CAPABILITY_ACTION,
        registry_origin,
        principal_type,
        principal_id,
        capability_key_id,
        issued_at
    );
    format!("0x{}", hex::encode(crate::ckb_blake2b256(material.as_bytes())))
}

struct GeneratedRegistryCapabilityKey {
    key_id: String,
    capability_pubkey: String,
}

struct GeneratedRegistryKeyMaterial {
    key_id: String,
    public_key: String,
    private_key_pkcs8: Vec<u8>,
}

const REGISTRY_KEYCHAIN_SECRET_SCHEMA: &str = "cellscript-registry-private-key-v1";

#[derive(serde::Deserialize, serde::Serialize)]
struct RegistryKeychainSecret {
    schema: String,
    status: String,
    pkcs8_b64: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pending_expires_at_unix_seconds: Option<u64>,
}

fn generate_registry_key_material() -> Result<GeneratedRegistryKeyMaterial> {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(&ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
        .map_err(|error| crate::error::CompileError::without_span(format!("failed to generate P-256 registry key: {:?}", error)))?;
    let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(&ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
        .map_err(|error| {
            crate::error::CompileError::without_span(format!("failed to load generated P-256 registry key: {:?}", error))
        })?;
    let spki = p256_spki_der_from_uncompressed_public_key(key_pair.public_key().as_ref())?;
    let public_key = format!("p256-spki:{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(spki));
    let key_id = registry_capability_key_id(&public_key);
    Ok(GeneratedRegistryKeyMaterial { key_id, public_key, private_key_pkcs8: pkcs8.as_ref().to_vec() })
}

fn generate_and_store_registry_capability_key() -> Result<GeneratedRegistryCapabilityKey> {
    let generated = generate_registry_key_material()?;
    store_registry_private_key(&generated.key_id, &generated.private_key_pkcs8)?;
    Ok(GeneratedRegistryCapabilityKey { key_id: generated.key_id, capability_pubkey: generated.public_key })
}

fn registry_capability_key_id(capability_pubkey: &str) -> String {
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(capability_pubkey.as_bytes());
    format!("cap_{}", &hex::encode(digest)[..32])
}

fn p256_spki_der_from_uncompressed_public_key(public_key: &[u8]) -> Result<Vec<u8>> {
    const P256_SPKI_PREFIX: &[u8] = &[
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03,
        0x01, 0x07, 0x03, 0x42, 0x00,
    ];
    if public_key.len() != 65 || public_key.first() != Some(&0x04) {
        return Err(crate::error::CompileError::without_span(format!(
            "generated registry public key must be an uncompressed 65-byte P-256 point, got {} bytes",
            public_key.len()
        )));
    }
    let mut spki = Vec::with_capacity(P256_SPKI_PREFIX.len() + public_key.len());
    spki.extend_from_slice(P256_SPKI_PREFIX);
    spki.extend_from_slice(public_key);
    Ok(spki)
}

fn store_registry_private_key(key_id: &str, pkcs8: &[u8]) -> Result<()> {
    store_registry_keychain_secret(
        key_id,
        &RegistryKeychainSecret {
            schema: REGISTRY_KEYCHAIN_SECRET_SCHEMA.to_string(),
            status: "active".to_string(),
            pkcs8_b64: base64::engine::general_purpose::STANDARD.encode(pkcs8),
            session_id: None,
            expires_at: None,
            pending_expires_at_unix_seconds: None,
        },
    )
}

fn store_pending_registry_private_key(key_id: &str, pkcs8: &[u8], session_id: &str, expires_at: &str) -> Result<()> {
    let pending_expires_at_unix_seconds =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs().saturating_add(15 * 60);
    store_registry_keychain_secret(
        key_id,
        &RegistryKeychainSecret {
            schema: REGISTRY_KEYCHAIN_SECRET_SCHEMA.to_string(),
            status: "pending".to_string(),
            pkcs8_b64: base64::engine::general_purpose::STANDARD.encode(pkcs8),
            session_id: Some(session_id.to_string()),
            expires_at: Some(expires_at.to_string()),
            pending_expires_at_unix_seconds: Some(pending_expires_at_unix_seconds),
        },
    )
}

fn store_registry_keychain_secret(key_id: &str, secret: &RegistryKeychainSecret) -> Result<()> {
    let encoded = serde_json::to_string(secret).map_err(|error| {
        crate::error::CompileError::without_span(format!("failed to encode registry private-key state: {error}"))
            .with_category(crate::error::CompileErrorCategory::Authentication)
    })?;
    let entry = keyring::Entry::new("cellscript-registry", key_id).map_err(|error| {
        crate::error::CompileError::without_span(format!("failed to open OS keychain: {}", error))
            .with_category(crate::error::CompileErrorCategory::Authentication)
            .with_source(error)
    })?;
    entry.set_password(&encoded).map_err(|error| {
        crate::error::CompileError::without_span(format!(
            "failed to store registry P-256 private key '{}' in OS keychain: {}",
            key_id, error
        ))
        .with_category(crate::error::CompileErrorCategory::Authentication)
        .with_source(error)
    })
}

fn remove_registry_private_key(key_id: &str) -> Result<()> {
    let entry = keyring::Entry::new("cellscript-registry", key_id).map_err(|error| {
        crate::error::CompileError::without_span(format!("failed to open OS keychain: {}", error))
            .with_category(crate::error::CompileErrorCategory::Authentication)
            .with_source(error)
    })?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(error) => Err(crate::error::CompileError::without_span(format!(
            "failed to remove pending registry private key '{}' from OS keychain: {}",
            key_id, error
        ))
        .with_category(crate::error::CompileErrorCategory::Authentication)
        .with_source(error)),
    }
}

fn write_new_reproducer_private_key(path: &Path, pkcs8: &[u8]) -> Result<()> {
    #[cfg(not(unix))]
    {
        let _ = (path, pkcs8);
        return Err(crate::error::CompileError::without_span(
            "--private-key-output requires Unix mode-0600 permission semantics; use the OS keychain on this platform",
        )
        .with_category(crate::error::CompileErrorCategory::Authentication));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        options.mode(0o600);
        let mut file = options.open(path).map_err(|error| {
            crate::error::CompileError::without_span(format!(
                "failed to create reproducer private-key file '{}': {}",
                path.display(),
                error
            ))
            .with_category(crate::error::CompileErrorCategory::Authentication)
            .with_source(error)
        })?;
        let secret = base64::engine::general_purpose::STANDARD.encode(pkcs8);
        file.write_all(secret.as_bytes()).and_then(|_| file.write_all(b"\n")).map_err(|error| {
            crate::error::CompileError::without_span(format!(
                "failed to write reproducer private-key file '{}': {}",
                path.display(),
                error
            ))
            .with_category(crate::error::CompileErrorCategory::Authentication)
            .with_source(error)
        })?;
        file.sync_all().map_err(|error| {
            crate::error::CompileError::without_span(format!(
                "failed to sync reproducer private-key file '{}': {}",
                path.display(),
                error
            ))
            .with_category(crate::error::CompileErrorCategory::Authentication)
            .with_source(error)
        })
    }
}

fn sign_registry_publish_payload(key_id: &str, canonical_payload: &str) -> Result<String> {
    sign_registry_capability_payload(key_id, canonical_payload)
}

pub(super) fn sign_registry_capability_payload(key_id: &str, canonical_payload: &str) -> Result<String> {
    let Some(pkcs8) = load_registry_capability_private_key(key_id)? else {
        return Err(
            crate::error::CompileError::without_span(format!(
                "capability signature is required for public publish and no private key was found for '{}' in the OS keychain; pass --capability-signature, set CELLSCRIPT_CAPABILITY_SIGNATURE, or set CELLSCRIPT_CAPABILITY_PRIVATE_KEY_PKCS8_B64 for CI",
                key_id
            ))
            .with_category(crate::error::CompileErrorCategory::Authentication),
        );
    };
    sign_registry_publish_payload_with_pkcs8(&pkcs8, canonical_payload)
}

pub(super) fn sign_registry_reproducer_payload(key_id: &str, canonical_payload: &str) -> Result<String> {
    let Some(pkcs8) = load_registry_reproducer_private_key(key_id)? else {
        return Err(
            crate::error::CompileError::without_span(format!(
                "reproducer signature key '{}' was not found in the OS keychain; set CELLSCRIPT_REPRODUCER_PRIVATE_KEY_PKCS8_B64 for an isolated builder",
                key_id
            ))
            .with_category(crate::error::CompileErrorCategory::Authentication),
        );
    };
    sign_registry_publish_payload_with_pkcs8(&pkcs8, canonical_payload)
}

fn load_registry_capability_private_key(key_id: &str) -> Result<Option<Vec<u8>>> {
    if let Ok(value) = std::env::var("CELLSCRIPT_CAPABILITY_PRIVATE_KEY_PKCS8_B64") {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            let decoded = base64::engine::general_purpose::STANDARD.decode(trimmed).map_err(|error| {
                crate::error::CompileError::without_span(format!(
                    "failed to decode CELLSCRIPT_CAPABILITY_PRIVATE_KEY_PKCS8_B64: {}",
                    error
                ))
            })?;
            return Ok(Some(decoded));
        }
    }

    load_registry_keychain_private_key(key_id)
}

fn load_registry_reproducer_private_key(key_id: &str) -> Result<Option<Vec<u8>>> {
    if let Ok(value) = std::env::var("CELLSCRIPT_REPRODUCER_PRIVATE_KEY_PKCS8_B64") {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            let decoded = base64::engine::general_purpose::STANDARD.decode(trimmed).map_err(|error| {
                crate::error::CompileError::without_span(format!(
                    "failed to decode CELLSCRIPT_REPRODUCER_PRIVATE_KEY_PKCS8_B64: {}",
                    error
                ))
            })?;
            return Ok(Some(decoded));
        }
    }

    load_registry_keychain_private_key(key_id)
}

fn load_registry_keychain_private_key(key_id: &str) -> Result<Option<Vec<u8>>> {
    let entry = keyring::Entry::new("cellscript-registry", key_id).map_err(|error| {
        crate::error::CompileError::without_span(format!("failed to open OS keychain: {}", error))
            .with_category(crate::error::CompileErrorCategory::Authentication)
            .with_source(error)
    })?;
    match entry.get_password() {
        Ok(secret) => {
            let trimmed = secret.trim();
            let encoded = if trimmed.starts_with('{') {
                let stored: RegistryKeychainSecret = serde_json::from_str(trimmed).map_err(|error| {
                    crate::error::CompileError::without_span(format!(
                        "failed to decode registry private-key state '{}' from OS keychain: {}",
                        key_id, error
                    ))
                    .with_category(crate::error::CompileErrorCategory::Authentication)
                })?;
                if stored.schema != REGISTRY_KEYCHAIN_SECRET_SCHEMA || !matches!(stored.status.as_str(), "pending" | "active") {
                    return Err(crate::error::CompileError::without_span(format!(
                        "registry private key '{}' has an unsupported OS keychain state",
                        key_id
                    ))
                    .with_category(crate::error::CompileErrorCategory::Authentication));
                }
                // A process may exit after the wallet commits authority but before the CLI
                // observes it. Only an observed terminal session state may remove a pending
                // key; local time alone cannot distinguish that case from an abandoned session.
                stored.pkcs8_b64
            } else {
                // Compatibility with keys written before the key lifecycle envelope was introduced.
                trimmed.to_string()
            };
            let decoded = base64::engine::general_purpose::STANDARD.decode(encoded.trim()).map_err(|error| {
                crate::error::CompileError::without_span(format!(
                    "failed to decode capability private key '{}' from OS keychain: {}",
                    key_id, error
                ))
            })?;
            Ok(Some(decoded))
        }
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => Err(crate::error::CompileError::without_span(format!(
            "failed to read capability private key '{}' from OS keychain: {}",
            key_id, error
        ))
        .with_category(crate::error::CompileErrorCategory::Authentication)
        .with_source(error)),
    }
}

fn sign_registry_publish_payload_with_pkcs8(pkcs8: &[u8], canonical_payload: &str) -> Result<String> {
    let rng = ring::rand::SystemRandom::new();
    let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(&ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8, &rng)
        .map_err(|error| crate::error::CompileError::without_span(format!("failed to load capability private key: {:?}", error)))?;
    let signature = key_pair
        .sign(&rng, canonical_payload.as_bytes())
        .map_err(|error| crate::error::CompileError::without_span(format!("failed to sign publish payload: {:?}", error)))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.as_ref()))
}

fn registry_publish_nonce(
    registry_origin: &str,
    namespace: &str,
    name: &str,
    version: &str,
    source_hash: &str,
    capability_key_id: &str,
    issued_at: &str,
) -> String {
    let material = format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        crate::package::registry::REGISTRY_PUBLISH_PROTOCOL,
        registry_origin,
        namespace,
        name,
        version,
        source_hash,
        capability_key_id,
        issued_at
    );
    format!("0x{}", hex::encode(crate::ckb_blake2b256(material.as_bytes())))
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DeclaredArtifactManifest {
    schema: String,
    namespace: String,
    name: String,
    release: String,
    kind: String,
    language: String,
    bundle: PathBuf,
    #[serde(default)]
    description: String,
    #[serde(default)]
    repository: String,
    #[serde(default)]
    homepage: String,
    #[serde(default)]
    documentation: String,
    #[serde(default)]
    keywords: Vec<String>,
    #[serde(default)]
    categories: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DeclaredArtifactBundle {
    schema: String,
    namespace: String,
    name: String,
    release: String,
    profile: String,
    manifest_json: String,
    objects: Vec<DeclaredArtifactBundleObject>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DeclaredArtifactBundleObject {
    role: String,
    content_base64: String,
}

fn publish_declared_artifact(args: PublishArgs, manifest_path: &Path) -> Result<()> {
    if args.payload.is_some() || args.source_snapshot.is_some() {
        return Err(crate::error::CompileError::without_span(
            "--artifact-manifest owns the publish payload and immutable bundle; do not combine it with --payload or --source-snapshot",
        ));
    }
    let manifest_text = std::fs::read_to_string(manifest_path).map_err(|error| {
        crate::error::CompileError::without_span(format!("failed to read artifact manifest '{}': {}", manifest_path.display(), error))
    })?;
    let manifest: DeclaredArtifactManifest = toml::from_str(&manifest_text).map_err(|error| {
        crate::error::CompileError::without_span(format!("failed to parse artifact manifest '{}': {}", manifest_path.display(), error))
    })?;
    if manifest.schema != "cellscript-registry-artifact" {
        return Err(crate::error::CompileError::without_span("Artifact.toml schema must be 'cellscript-registry-artifact'"));
    }
    validate_declared_artifact_ident(&manifest.namespace, "namespace")?;
    validate_declared_artifact_ident(&manifest.name, "name")?;
    validate_declared_artifact_release(&manifest.release)?;
    let artifact = declared_artifact_descriptor(&manifest.kind, &manifest.language)?;
    let manifest_dir = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    let bundle_path = if manifest.bundle.is_absolute() { manifest.bundle.clone() } else { manifest_dir.join(&manifest.bundle) };
    let bundle_bytes = std::fs::read(&bundle_path).map_err(|error| {
        crate::error::CompileError::without_span(format!("failed to read artifact bundle '{}': {}", bundle_path.display(), error))
    })?;
    if bundle_bytes.is_empty() || bundle_bytes.len() > 5 * 1024 * 1024 {
        return Err(crate::error::CompileError::without_span("artifact bundle must be a non-empty JSON file no larger than 5 MiB"));
    }
    let bundle: DeclaredArtifactBundle = serde_json::from_slice(&bundle_bytes).map_err(|error| {
        crate::error::CompileError::without_span(format!("failed to parse artifact bundle '{}': {}", bundle_path.display(), error))
    })?;
    if bundle.schema != "cellscript-registry-bundle"
        || bundle.namespace != manifest.namespace
        || bundle.name != manifest.name
        || bundle.release != manifest.release
        || bundle.profile != artifact.profile
    {
        return Err(crate::error::CompileError::without_span(
            "artifact bundle schema, coordinate, release, or profile does not match Artifact.toml",
        ));
    }
    let manifest_json: serde_json::Value = serde_json::from_str(&bundle.manifest_json).map_err(|error| {
        crate::error::CompileError::without_span(format!("artifact bundle manifest_json must be valid JSON: {error}"))
    })?;
    if !manifest_json.is_object() {
        return Err(crate::error::CompileError::without_span("artifact bundle manifest_json must encode a JSON object"));
    }
    validate_declared_bundle_roles(&bundle, &artifact.profile, &manifest_json)?;
    let source = declared_bundle_object(&bundle, "source")?;
    let source_hash = hex::encode(crate::ckb_blake2b256(&source));
    let mut artifact_hash = None;
    let mut abi_hash = None;
    let mut abi_sha256 = None;
    let mut executable_ls_idl_bound = None;
    let mut build_recipe_hash = None;
    let audit_report_hash = if manifest_json.pointer("/security/audit_report_hash").is_some() {
        Some(hex::encode(crate::ckb_blake2b256(&declared_bundle_object(&bundle, "audit_report")?)))
    } else {
        None
    };
    if artifact.profile == "ckb_executable" {
        let executable = declared_bundle_object(&bundle, "executable")?;
        let abi = declared_bundle_object(&bundle, "abi")?;
        artifact_hash = Some(hex::encode(crate::ckb_blake2b256(&executable)));
        abi_hash = Some(hex::encode(crate::ckb_blake2b256(&abi)));
        if manifest_json.get("interface").is_some() {
            use sha2::Digest as _;
            crate::package::registry::validate_ls_idl_document(&abi).map_err(crate::error::CompileError::without_span)?;
            let digest = sha2::Sha256::digest(&abi);
            abi_sha256 = Some(hex::encode(digest));
            executable_ls_idl_bound = Some(executable.ends_with(digest.as_slice()));
        }
        if manifest_json.pointer("/build/reproducible").and_then(serde_json::Value::as_bool) == Some(true) {
            build_recipe_hash = Some(hex::encode(crate::ckb_blake2b256(&declared_bundle_object(&bundle, "build_recipe")?)));
        }
    } else if artifact.profile == "reproducible_build" {
        artifact_hash = Some(hex::encode(crate::ckb_blake2b256(&declared_bundle_object(&bundle, "executable")?)));
        build_recipe_hash = Some(hex::encode(crate::ckb_blake2b256(&declared_bundle_object(&bundle, "build_recipe")?)));
    }
    crate::package::registry::validate_artifact_profile_contract(
        &artifact.kind,
        &artifact.profile,
        &manifest_json,
        crate::package::registry::ArtifactContractHashes {
            artifact_hash: artifact_hash.as_deref(),
            abi_hash: abi_hash.as_deref(),
            abi_sha256: abi_sha256.as_deref(),
            executable_ls_idl_bound,
            build_recipe_hash: build_recipe_hash.as_deref(),
            audit_report_hash: audit_report_hash.as_deref(),
        },
    )
    .map_err(crate::error::CompileError::without_span)?;
    let canonical_manifest_json = crate::package::registry::canonical_artifact_contract_json(&manifest_json)
        .map_err(crate::error::CompileError::without_span)?;
    let manifest_hash = hex::encode(crate::ckb_blake2b256(canonical_manifest_json.as_bytes()));
    let mut release = serde_json::json!({
        "version": manifest.release,
        "tag": format!("v{}", manifest.release),
        "source_hash": source_hash,
        "verification_status": "pending",
        "deployment_status": if artifact.profile == "ckb_executable" { "undeployed" } else { "not_applicable" },
        "availability_status": "active",
        "profile_contract": manifest_json,
    });
    if let Some(value) = artifact_hash {
        release["artifact_hash"] = serde_json::Value::String(value);
    }
    if let Some(value) = abi_hash {
        release["abi_hash"] = serde_json::Value::String(value);
    }
    if let Some(value) = build_recipe_hash {
        release["build_recipe_hash"] = serde_json::Value::String(value);
    }
    let mut registry_entry = serde_json::json!({
        "schema_version": crate::package::registry::RegistryIndex::CURRENT_SCHEMA_VERSION,
        "namespace": manifest.namespace,
        "name": manifest.name,
        "artifact": artifact,
        "versions": [release],
    });
    let entry = registry_entry.as_object_mut().expect("registry entry JSON object");
    for (key, value) in [
        ("description", &manifest.description),
        ("repository", &manifest.repository),
        ("homepage", &manifest.homepage),
        ("documentation", &manifest.documentation),
    ] {
        if !value.is_empty() {
            entry.insert(key.to_string(), serde_json::Value::String(value.clone()));
        }
    }
    if !manifest.keywords.is_empty() {
        entry.insert(
            "keywords".to_string(),
            serde_json::to_value(&manifest.keywords).map_err(|error| {
                crate::error::CompileError::without_span(format!("failed to serialize artifact keywords: {error}"))
            })?,
        );
    }
    if !manifest.categories.is_empty() {
        entry.insert(
            "categories".to_string(),
            serde_json::to_value(&manifest.categories).map_err(|error| {
                crate::error::CompileError::without_span(format!("failed to serialize artifact categories: {error}"))
            })?,
        );
    }

    if args.dry_run {
        let summary = serde_json::json!({
            "status": "valid",
            "coordinate": format!("{}/{}@{}", manifest.namespace, manifest.name, manifest.release),
            "artifact": artifact,
            "source_hash": source_hash,
            "manifest_hash": manifest_hash,
            "bundle": bundle_path,
        });
        if args.json {
            return print_json(&summary);
        }
        println!("{}", "Artifact publish dry-run passed".green());
        println!("  Coordinate: {}/{}@{}", manifest.namespace, manifest.name, manifest.release);
        println!("  Kind: {}", artifact.kind);
        println!("  Profile: {}", artifact.profile);
        println!("  Source hash: {}", source_hash);
        return Ok(());
    }

    let api_base = resolve_registry_api_base(args.api_url)?;
    let registry_origin = registry_origin_from_api_base(&api_base)?;
    let endpoint = registry_publish_endpoint(&api_base, &manifest.namespace, &manifest.name);
    let capability_key_id = match args.capability_key_id.or_else(|| std::env::var("CELLSCRIPT_CAPABILITY_KEY_ID").ok()) {
        Some(key_id) => key_id,
        None if args.authorise => {
            authorise_registry_publish_key(&api_base, &manifest.namespace, &manifest.name, &artifact.kind, args.no_open)?
        }
        None => {
            return Err(crate::error::CompileError::without_span(format!(
                "publishing {}/{} requires a wallet-authorised publishing key; run `cellc publish --authorise` for the continuous browser flow, or pass an existing --capability-key-id",
                manifest.namespace, manifest.name
            ))
            .with_category(crate::error::CompileErrorCategory::Authentication));
        }
    };
    let issued_at = current_utc_timestamp();
    let expires_at = utc_timestamp_after_seconds(10 * 60);
    let nonce = registry_publish_nonce(
        &registry_origin,
        &manifest.namespace,
        &manifest.name,
        &manifest.release,
        &source_hash,
        &capability_key_id,
        &issued_at,
    );
    let payload = crate::package::registry::RegistryPublishPayload {
        protocol: crate::package::registry::REGISTRY_PUBLISH_PROTOCOL.to_string(),
        action: crate::package::registry::PUBLISH_ACTION.to_string(),
        registry_origin,
        namespace: manifest.namespace,
        name: manifest.name,
        version: manifest.release,
        source_hash: source_hash.clone(),
        manifest_hash,
        capability_key_id,
        nonce,
        issued_at,
        expires_at,
        cli_version: crate::VERSION.to_string(),
        artifact,
        registry_entry,
    };
    let canonical_payload = registry_publish_canonical_payload(&payload)?;
    if args.print_payload {
        return print_json(&serde_json::json!({ "endpoint": endpoint, "payload": payload, "canonical_payload": canonical_payload }));
    }
    let capability_signature =
        if let Some(signature) = args.capability_signature.or_else(|| std::env::var("CELLSCRIPT_CAPABILITY_SIGNATURE").ok()) {
            signature
        } else {
            sign_registry_publish_payload(&payload.capability_key_id, &canonical_payload)?
        };
    let request = crate::package::registry::RegistryPublishRequest {
        payload,
        capability_signature: crate::package::registry::RegistryCapabilitySignature {
            algorithm: "p256-sha256".to_string(),
            signature: capability_signature,
        },
        source_snapshot: crate::package::registry::RegistrySourceSnapshot {
            content_base64: base64::engine::general_purpose::STANDARD.encode(&bundle_bytes),
            content_type: "application/vnd.cellscript.artifact-bundle+json".to_string(),
            size_bytes: bundle_bytes.len() as u64,
            source_hash,
        },
    };
    let idempotency_key = resolve_registry_publish_idempotency_key(args.idempotency_key.as_deref(), &request)?;
    submit_registry_publish_request(&endpoint, &request, &idempotency_key, args.json)
}

fn declared_artifact_descriptor(kind: &str, language: &str) -> Result<crate::package::registry::RegistryArtifactDescriptor> {
    let allowed_language = match kind {
        "runtime_verifier" | "deployable_contract" => matches!(language, "cellscript" | "rust" | "c" | "javascript" | "other"),
        "reproducible_binary" => matches!(language, "rust" | "c" | "other"),
        "template" => matches!(language, "cellscript" | "rust" | "c" | "javascript" | "other" | "unspecified"),
        "source_library" | "profile_library" => {
            return Err(crate::error::CompileError::without_span(
                "source_library and profile_library use the native CellScript package publish path",
            ));
        }
        _ => return Err(crate::error::CompileError::without_span(format!("unknown artifact kind '{kind}'"))),
    };
    if !allowed_language {
        return Err(crate::error::CompileError::without_span(format!(
            "language '{language}' is not valid for artifact kind '{kind}'"
        )));
    }
    let (profile, consumption_mode) = match kind {
        "runtime_verifier" => ("ckb_executable", "tcb"),
        "deployable_contract" => ("ckb_executable", "deployment"),
        "reproducible_binary" => ("reproducible_build", "tcb"),
        "template" => ("copy_material", "copy"),
        _ => unreachable!("artifact kind was checked above"),
    };
    Ok(crate::package::registry::RegistryArtifactDescriptor {
        kind: kind.to_string(),
        profile: profile.to_string(),
        consumption_mode: consumption_mode.to_string(),
        language: language.to_string(),
    })
}

fn declared_bundle_object(bundle: &DeclaredArtifactBundle, role: &str) -> Result<Vec<u8>> {
    let mut objects = bundle.objects.iter().filter(|object| object.role == role);
    let object = objects
        .next()
        .ok_or_else(|| crate::error::CompileError::without_span(format!("artifact bundle is missing required '{role}' object")))?;
    if objects.next().is_some() {
        return Err(crate::error::CompileError::without_span(format!("artifact bundle contains more than one '{role}' object")));
    }
    let bytes = base64::engine::general_purpose::STANDARD.decode(&object.content_base64).map_err(|error| {
        crate::error::CompileError::without_span(format!("artifact bundle '{role}' object is not valid base64: {error}"))
    })?;
    if bytes.is_empty() {
        return Err(crate::error::CompileError::without_span(format!("artifact bundle '{role}' object must not be empty")));
    }
    Ok(bytes)
}

fn validate_declared_bundle_roles(bundle: &DeclaredArtifactBundle, profile: &str, contract: &serde_json::Value) -> Result<()> {
    let mut required = match profile {
        "ckb_executable" => vec!["source", "executable", "abi"],
        "reproducible_build" => vec!["source", "executable", "build_recipe"],
        "copy_material" => vec!["source"],
        other => {
            return Err(crate::error::CompileError::without_span(format!("unsupported declared artifact profile '{other}'")));
        }
    };
    if contract.pointer("/security/audit_report_hash").is_some() {
        required.push("audit_report");
    }
    if profile == "ckb_executable" && contract.pointer("/build/reproducible").and_then(serde_json::Value::as_bool) == Some(true) {
        required.push("build_recipe");
    }
    let mut seen = BTreeSet::new();
    for object in &bundle.objects {
        if !required.contains(&object.role.as_str()) {
            return Err(crate::error::CompileError::without_span(format!(
                "artifact bundle role '{}' is not allowed for profile '{profile}'",
                object.role
            )));
        }
        if !seen.insert(object.role.as_str()) {
            return Err(crate::error::CompileError::without_span(format!(
                "artifact bundle contains more than one '{}' object",
                object.role
            )));
        }
    }
    for role in required {
        if !seen.contains(role) {
            return Err(crate::error::CompileError::without_span(format!("artifact bundle is missing required '{role}' object")));
        }
    }
    Ok(())
}

fn validate_declared_artifact_ident(value: &str, field: &str) -> Result<()> {
    let bytes = value.as_bytes();
    let edge = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    if bytes.is_empty()
        || bytes.len() > 64
        || !edge(bytes[0])
        || !edge(*bytes.last().expect("non-empty identifier"))
        || !bytes.iter().all(|byte| edge(*byte) || matches!(*byte, b'_' | b'-'))
    {
        return Err(crate::error::CompileError::without_span(format!(
            "artifact {field} must be 1-64 lowercase letters or numbers, with '_' or '-' only between characters"
        )));
    }
    Ok(())
}

fn validate_declared_artifact_release(value: &str) -> Result<()> {
    let mut core = value.split(['-', '+']).next().unwrap_or_default().split('.');
    let valid = (0..3).all(|_| core.next().is_some_and(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit())))
        && core.next().is_none();
    if !valid {
        return Err(crate::error::CompileError::without_span("artifact release must be semver-like"));
    }
    Ok(())
}

fn build_publish_registry_version(
    manifest: &PackageManifest,
    result: &crate::CompileResult,
    source_hash: &str,
) -> Result<crate::package::registry::RegistryVersion> {
    let mut deps = BTreeMap::new();
    for (dep_name, dep) in &manifest.dependencies {
        let (namespace, version) = match dep {
            crate::package::Dependency::Simple(version) => (manifest.package.namespace.clone().unwrap_or_default(), version.clone()),
            crate::package::Dependency::Detailed(detail) => {
                let namespace = detail.namespace.clone().unwrap_or_else(|| manifest.package.namespace.clone().unwrap_or_default());
                (namespace, detail.version.clone())
            }
        };
        deps.insert(dep_name.clone(), crate::package::registry::RegistryDependencyRef { namespace, version });
    }

    Ok(crate::package::registry::RegistryVersion {
        version: manifest.package.version.clone(),
        tag: format!("v{}", manifest.package.version),
        source_hash: source_hash.to_string(),
        cellscript_version: result.metadata.compiler_version.clone(),
        edition: result.metadata.edition,
        compatibility_profile_hash: hash_json_value("compatibility_profile", &result.metadata.compatibility_profile)?,
        dependencies: deps,
        abi_index: Some(metadata_abi_hash(&result.metadata)?),
        schema_hash: Some(result.metadata.molecule_schema_manifest.manifest_hash.clone()),
        license: if manifest.package.license.is_empty() { None } else { Some(manifest.package.license.clone()) },
        released_at: Some(current_utc_timestamp()),
        status: crate::package::registry::RegistryEntryStatus::SourcePublished,
        yanked: false,
        yanked_at: None,
        yanked_reason: None,
        replaced_by: None,
        audit: None,
    })
}

fn build_publish_registry_entry(
    manifest: &PackageManifest,
    namespace: &str,
    version_entry: crate::package::registry::RegistryVersion,
    artifact: &crate::package::registry::RegistryArtifactDescriptor,
    public_interface: &crate::interface::PackageInterface,
    interface_hash: &str,
) -> Result<serde_json::Value> {
    let index = crate::package::registry::RegistryIndex {
        schema_version: crate::package::registry::RegistryIndex::CURRENT_SCHEMA_VERSION,
        name: manifest.package.name.clone(),
        namespace: namespace.to_string(),
        versions: vec![version_entry],
    };
    let mut value = serde_json::to_value(index).map_err(|error| {
        crate::error::CompileError::without_span(format!("failed to serialize registry entry for publish: {}", error))
    })?;
    let Some(object) = value.as_object_mut() else {
        return Err(crate::error::CompileError::without_span("registry entry did not serialize as a JSON object"));
    };
    object.insert(
        "artifact".to_string(),
        serde_json::to_value(artifact).map_err(|error| {
            crate::error::CompileError::without_span(format!("failed to serialize CellScript artifact descriptor: {}", error))
        })?,
    );
    let published = object
        .get_mut("versions")
        .and_then(serde_json::Value::as_array_mut)
        .and_then(|versions| versions.first_mut())
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| crate::error::CompileError::without_span("registry entry has no publish release"))?;
    published.remove("status");
    published.remove("yanked");
    published.insert("verification_status".to_string(), serde_json::Value::String("pending".to_string()));
    published.insert("interface_hash".to_string(), serde_json::Value::String(interface_hash.to_string()));
    published.insert(
        "interface".to_string(),
        serde_json::to_value(public_interface).map_err(|error| {
            crate::error::CompileError::without_span(format!("failed to serialize canonical public interface: {error}"))
        })?,
    );
    published.insert("deployment_status".to_string(), serde_json::Value::String("not_applicable".to_string()));
    published.insert("availability_status".to_string(), serde_json::Value::String("active".to_string()));
    if !manifest.package.repository.is_empty() {
        object.insert("repository".to_string(), serde_json::Value::String(manifest.package.repository.clone()));
    }
    if !manifest.package.description.is_empty() {
        object.insert("description".to_string(), serde_json::Value::String(manifest.package.description.clone()));
    }
    if !manifest.package.homepage.is_empty() {
        object.insert("homepage".to_string(), serde_json::Value::String(manifest.package.homepage.clone()));
    }
    if !manifest.package.documentation.is_empty() {
        object.insert("documentation".to_string(), serde_json::Value::String(manifest.package.documentation.clone()));
    }
    if !manifest.package.keywords.is_empty() {
        object.insert(
            "keywords".to_string(),
            serde_json::to_value(&manifest.package.keywords).map_err(|error| {
                crate::error::CompileError::without_span(format!("failed to serialize package keywords for publish: {}", error))
            })?,
        );
    }
    if !manifest.package.categories.is_empty() {
        object.insert(
            "categories".to_string(),
            serde_json::to_value(&manifest.package.categories).map_err(|error| {
                crate::error::CompileError::without_span(format!("failed to serialize package categories for publish: {}", error))
            })?,
        );
    }
    Ok(value)
}

fn cellscript_artifact_descriptor(kind: Option<&str>) -> Result<crate::package::registry::RegistryArtifactDescriptor> {
    let kind = kind.unwrap_or("source_library");
    if !matches!(kind, "source_library" | "profile_library") {
        return Err(crate::error::CompileError::without_span(
            "CellScript package artifact kind must be source_library or profile_library",
        ));
    }
    Ok(crate::package::registry::RegistryArtifactDescriptor {
        kind: kind.to_string(),
        profile: "cellscript_source".to_string(),
        consumption_mode: "dependency".to_string(),
        language: "cellscript".to_string(),
    })
}

pub(super) fn resolve_registry_api_base(api_url: Option<String>) -> Result<String> {
    let value = api_url
        .or_else(|| std::env::var("CELLSCRIPT_REGISTRY_API_URL").ok())
        .or_else(|| std::env::var("CELLSCRIPT_REGISTRY_ORIGIN").ok())
        .unwrap_or_else(|| crate::package::registry::DEFAULT_PUBLIC_REGISTRY_ORIGIN.to_string());
    let trimmed = value.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(crate::error::CompileError::without_span("registry API URL is empty"));
    }
    let _ = parse_registry_api_url(trimmed)?;
    Ok(trimmed.to_string())
}

pub(super) fn registry_origin_from_api_base(api_base: &str) -> Result<String> {
    Ok(parse_registry_api_url(api_base)?.origin().ascii_serialization())
}

fn parse_registry_api_url(api_base: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(api_base)
        .map_err(|error| crate::error::CompileError::without_span(format!("invalid registry API URL '{}': {}", api_base, error)))?;
    let Some(host) = url.host_str() else {
        return Err(crate::error::CompileError::without_span(format!("registry API URL '{}' has no host", api_base)));
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let is_loopback =
        host.eq_ignore_ascii_case("localhost") || host.parse::<std::net::IpAddr>().is_ok_and(|address| address.is_loopback());
    match url.scheme() {
        "https" => {}
        "http" if is_loopback => {}
        "http" => {
            return Err(crate::error::CompileError::without_span(
                "registry API URL must use HTTPS; plaintext HTTP is allowed only for loopback development servers",
            ));
        }
        scheme => {
            return Err(crate::error::CompileError::without_span(format!(
                "registry API URL '{}' uses unsupported scheme '{}'",
                api_base, scheme
            )));
        }
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(crate::error::CompileError::without_span("registry API URL must not contain credentials"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(crate::error::CompileError::without_span("registry API URL must not contain a query or fragment"));
    }
    Ok(url)
}

fn registry_publish_endpoint(api_base: &str, namespace: &str, name: &str) -> String {
    format!("{}/v1/artifacts/{}/{}/releases", api_base.trim_end_matches('/'), namespace, name)
}

fn resolve_registry_publish_idempotency_key(
    cli_value: Option<&str>,
    request: &crate::package::registry::RegistryPublishRequest,
) -> Result<String> {
    let value = if let Some(value) = cli_value {
        value.to_string()
    } else if let Ok(value) = std::env::var("CELLSCRIPT_REGISTRY_IDEMPOTENCY_KEY") {
        value
    } else {
        let digest = hash_json_value("registry publish request", request)?;
        format!("cellc-publish-{}", digest)
    };
    let trimmed = value.trim();
    if trimmed.len() < 16 || trimmed.len() > 160 || !trimmed.bytes().all(is_idempotency_key_byte) {
        return Err(crate::error::CompileError::without_span(
            "publish Idempotency-Key must be 16..160 ASCII token characters: letters, digits, '.', '_', ':', or '-'",
        ));
    }
    Ok(trimmed.to_string())
}

fn is_idempotency_key_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-')
}

fn read_registry_publish_payload(path: &Path) -> Result<crate::package::registry::RegistryPublishPayload> {
    let value = read_json_value(path)?;
    let payload_value = value.get("payload").cloned().unwrap_or(value);
    serde_json::from_value(payload_value).map_err(|error| {
        crate::error::CompileError::without_span(format!("failed to parse registry publish payload '{}': {}", path.display(), error))
    })
}

fn read_capability_authorisation_payload(path: &Path) -> Result<crate::package::registry::CapabilityAuthorisationPayload> {
    let value = read_json_value(path)?;
    let payload_value = value.get("payload").cloned().unwrap_or(value);
    serde_json::from_value(payload_value).map_err(|error| {
        crate::error::CompileError::without_span(format!(
            "failed to parse capability authorisation payload '{}': {}",
            path.display(),
            error
        ))
    })
}

fn read_capability_revocation_payload(path: &Path) -> Result<crate::package::registry::CapabilityRevocationPayload> {
    let value = read_json_value(path)?;
    let payload_value = value.get("payload").cloned().unwrap_or(value);
    serde_json::from_value(payload_value).map_err(|error| {
        crate::error::CompileError::without_span(format!(
            "failed to parse capability revocation payload '{}': {}",
            path.display(),
            error
        ))
    })
}

fn validate_publish_payload_matches_local_package(
    payload: &crate::package::registry::RegistryPublishPayload,
    registry_origin: &str,
    namespace: &str,
    manifest: &PackageManifest,
    source_hash: &str,
    public_interface: &crate::interface::PackageInterface,
    interface_hash: &str,
) -> Result<()> {
    if payload.protocol != crate::package::registry::REGISTRY_PUBLISH_PROTOCOL
        || payload.action != crate::package::registry::PUBLISH_ACTION
    {
        return Err(crate::error::CompileError::without_span("publish payload has the wrong protocol or action"));
    }
    if payload.registry_origin != registry_origin {
        return Err(crate::error::CompileError::without_span(format!(
            "publish payload registry_origin '{}' does not match API origin '{}'",
            payload.registry_origin, registry_origin
        )));
    }
    if payload.namespace != namespace || payload.name != manifest.package.name || payload.version != manifest.package.version {
        return Err(crate::error::CompileError::without_span(format!(
            "publish payload targets {}/{} v{}, but local package is {}/{} v{}",
            payload.namespace, payload.name, payload.version, namespace, manifest.package.name, manifest.package.version
        )));
    }
    if payload.source_hash != source_hash {
        return Err(crate::error::CompileError::without_span(format!(
            "publish payload source_hash '{}' does not match local source_hash '{}'",
            payload.source_hash, source_hash
        )));
    }
    let payload_interface_hash = payload
        .registry_entry
        .get("versions")
        .and_then(serde_json::Value::as_array)
        .and_then(|versions| versions.first())
        .and_then(|version| version.get("interface_hash"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if payload_interface_hash != interface_hash {
        return Err(crate::error::CompileError::without_span(format!(
            "publish payload interface_hash '{}' does not match local canonical interface '{}'",
            payload_interface_hash, interface_hash
        )));
    }
    let payload_interface = payload
        .registry_entry
        .get("versions")
        .and_then(serde_json::Value::as_array)
        .and_then(|versions| versions.first())
        .and_then(|version| version.get("interface"))
        .cloned()
        .ok_or_else(|| crate::error::CompileError::without_span("publish payload is missing the canonical public interface"))?;
    let payload_interface: crate::interface::PackageInterface = serde_json::from_value(payload_interface)
        .map_err(|error| crate::error::CompileError::without_span(format!("publish payload public interface is invalid: {error}")))?;
    if &payload_interface != public_interface || crate::interface::hash(&payload_interface) != interface_hash {
        return Err(crate::error::CompileError::without_span(
            "publish payload public interface does not match the locally compiled canonical interface",
        ));
    }
    if !matches!(payload.artifact.kind.as_str(), "source_library" | "profile_library")
        || payload.artifact.profile != "cellscript_source"
        || payload.artifact.consumption_mode != "dependency"
        || payload.artifact.language != "cellscript"
    {
        return Err(crate::error::CompileError::without_span(
            "CellScript package publish payload must declare the source_library/cellscript_source dependency contract",
        ));
    }
    Ok(())
}

fn registry_publish_canonical_payload(payload: &crate::package::registry::RegistryPublishPayload) -> Result<String> {
    let value = serde_json::to_value(payload)
        .map_err(|error| crate::error::CompileError::without_span(format!("failed to serialize publish payload: {}", error)))?;
    canonical_json_string(&value)
}

fn canonical_json_string(value: &serde_json::Value) -> Result<String> {
    serde_json::to_string(&sort_json_for_canonical(value))
        .map_err(|error| crate::error::CompileError::without_span(format!("failed to serialize canonical JSON: {}", error)))
}

fn sort_json_for_canonical(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Array(items) => serde_json::Value::Array(items.iter().map(sort_json_for_canonical).collect()),
        serde_json::Value::Object(object) => {
            let mut sorted = serde_json::Map::new();
            let mut keys: Vec<_> = object.keys().collect();
            keys.sort();
            for key in keys {
                if let Some(item) = object.get(key) {
                    sorted.insert(key.clone(), sort_json_for_canonical(item));
                }
            }
            serde_json::Value::Object(sorted)
        }
        other => other.clone(),
    }
}

fn build_registry_source_snapshot(
    source_snapshot: Option<&Path>,
    root: &Path,
    manifest: &PackageManifest,
    source_hash: &str,
) -> Result<crate::package::registry::RegistrySourceSnapshot> {
    let (bytes, content_type) = if let Some(path) = source_snapshot {
        let bytes = std::fs::read(path).map_err(|error| {
            crate::error::CompileError::without_span(format!("failed to read source snapshot '{}': {}", path.display(), error))
        })?;
        (bytes, source_snapshot_content_type(path).to_string())
    } else {
        (build_generated_source_snapshot_bytes(root, manifest)?, "application/vnd.cellscript.source-snapshot+json".to_string())
    };
    if bytes.is_empty() {
        return Err(crate::error::CompileError::without_span("source snapshot is empty"));
    }
    Ok(crate::package::registry::RegistrySourceSnapshot {
        content_base64: base64::engine::general_purpose::STANDARD.encode(&bytes),
        content_type,
        size_bytes: bytes.len() as u64,
        source_hash: source_hash.to_string(),
    })
}

fn source_snapshot_content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|ext| ext.to_str()).unwrap_or_default() {
        "json" => "application/vnd.cellscript.source-snapshot+json",
        "tar" => "application/x-tar",
        "tgz" | "gz" => "application/gzip",
        _ => "application/octet-stream",
    }
}

fn build_generated_source_snapshot_bytes(root: &Path, manifest: &PackageManifest) -> Result<Vec<u8>> {
    let files = collect_publish_snapshot_files(root, manifest)?;
    let mut entries = Vec::new();
    for path in files {
        let bytes = std::fs::read(&path)
            .map_err(|error| crate::error::CompileError::without_span(format!("failed to read '{}': {}", path.display(), error)))?;
        entries.push(serde_json::json!({
            "path": normalized_relative_path(root, &path),
            "blake2b256": crate::hex_encode(&crate::ckb_blake2b256(&bytes)),
            "content_base64": base64::engine::general_purpose::STANDARD.encode(&bytes),
        }));
    }
    let snapshot = serde_json::json!({
        "schema": "cellscript-source-snapshot-v1",
        "generated_by": crate::VERSION,
        "package": {
            "namespace": manifest.package.namespace.as_deref(),
            "name": &manifest.package.name,
            "version": &manifest.package.version,
        },
        "files": entries,
    });
    serde_json::to_vec(&snapshot)
        .map_err(|error| crate::error::CompileError::without_span(format!("failed to serialize generated source snapshot: {}", error)))
}

fn collect_publish_snapshot_files(root: &Path, manifest: &PackageManifest) -> Result<Vec<PathBuf>> {
    let mut files = BTreeSet::new();
    let manifest_path = root.join("Cell.toml");
    if manifest_path.is_file() {
        files.insert(manifest_path);
    }
    let lockfile_path = root.join("Cell.lock");
    if lockfile_path.is_file() {
        files.insert(lockfile_path);
    }

    if manifest.package.source_roots.is_empty() {
        let src = root.join("src");
        if src.is_dir() {
            collect_publish_snapshot_cell_files(&src, &mut files)?;
        }
    } else {
        for source_root in &manifest.package.source_roots {
            let path = root.join(source_root);
            if !path.exists() {
                return Err(crate::error::CompileError::without_span(format!(
                    "configured source root '{}' does not exist",
                    path.display()
                )));
            }
            if path.is_dir() {
                collect_publish_snapshot_cell_files(&path, &mut files)?;
            } else if path.extension().is_some_and(|ext| ext == "cell") {
                files.insert(path);
            }
        }
    }

    let entry_path = root.join(&manifest.package.entry);
    if entry_path.is_file() {
        files.insert(entry_path);
    }
    Ok(files.into_iter().collect())
}

fn collect_publish_snapshot_cell_files(dir: &Path, files: &mut BTreeSet<PathBuf>) -> Result<()> {
    let entries = std::fs::read_dir(dir).map_err(|error| {
        crate::error::CompileError::without_span(format!("failed to read directory '{}': {}", dir.display(), error))
    })?;
    for entry in entries {
        let entry =
            entry.map_err(|error| crate::error::CompileError::without_span(format!("failed to read directory entry: {}", error)))?;
        let path = entry.path();
        if path.is_dir() {
            collect_publish_snapshot_cell_files(&path, files)?;
        } else if path.extension().is_some_and(|ext| ext == "cell") {
            files.insert(path);
        }
    }
    Ok(())
}

fn normalized_relative_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root).unwrap_or(path).to_string_lossy().replace('\\', "/")
}

fn submit_registry_publish_request(
    endpoint: &str,
    request: &crate::package::registry::RegistryPublishRequest,
    idempotency_key: &str,
    json_output: bool,
) -> Result<()> {
    let client = registry_http_client()?;
    let response = submit_registry_publish_request_with_retry(&client, endpoint, request, idempotency_key)?;
    let status = response.status();
    let body = response.text().map_err(|error| {
        crate::error::CompileError::without_span(format!("failed to read registry publish response from '{}': {}", endpoint, error))
            .with_category(crate::error::CompileErrorCategory::Network)
            .with_source(error)
    })?;
    if !status.is_success() {
        return Err(crate::error::CompileError::without_span(format!(
            "registry publish request failed with HTTP {}: {}",
            status,
            body.trim()
        ))
        .with_category(registry_http_error_category(status)));
    }

    let parsed = serde_json::from_str::<serde_json::Value>(&body).unwrap_or_else(|_| serde_json::json!({ "response": body }));
    if json_output {
        print_json(&parsed)?;
    } else {
        println!("{}", "Published to registry write API".green());
        if let Some(status) = parsed.get("status").and_then(serde_json::Value::as_str) {
            println!("  Status: {}", status);
        }
        if let Some(direct_url) = parsed.get("direct_url").and_then(serde_json::Value::as_str) {
            println!("  Direct URL: {}", direct_url);
        }
        if let Some(request_id) = parsed.get("request_id").and_then(serde_json::Value::as_str) {
            println!("  Request id: {}", request_id);
        }
    }
    Ok(())
}

pub(super) fn registry_http_client() -> Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder().timeout(Duration::from_secs(30)).redirect(reqwest::redirect::Policy::none()).build().map_err(
        |error| {
            crate::error::CompileError::without_span(format!("failed to build registry HTTP client: {}", error))
                .with_category(crate::error::CompileErrorCategory::Network)
                .with_source(error)
        },
    )
}

#[derive(serde::Serialize)]
struct RegistryAuthorisationSessionCreateRequest {
    capability_pubkey: String,
    requested_scopes: Vec<String>,
    artifact_kind: String,
    capability_expires_at: String,
    cli_version: String,
}

#[derive(serde::Deserialize)]
struct RegistryAuthorisationSessionCreateResponse {
    session_id: String,
    poll_token: String,
    browser_url: String,
    expires_at: String,
}

#[derive(serde::Deserialize)]
struct RegistryAuthorisationSessionPollResponse {
    status: String,
    capability_key_id: Option<String>,
    namespace_status: Option<String>,
}

enum RegistryAuthorisationSessionPollOutcome {
    Expired,
    State(RegistryAuthorisationSessionPollResponse),
}

fn fetch_registry_authorisation_session(
    client: &reqwest::blocking::Client,
    endpoint: &str,
    poll_token: &str,
) -> Result<RegistryAuthorisationSessionPollOutcome> {
    let response = client.get(endpoint).bearer_auth(poll_token).send().map_err(|error| {
        crate::error::CompileError::without_span(format!("failed to poll browser authorisation session: {error}"))
            .with_category(crate::error::CompileErrorCategory::Network)
            .with_source(error)
    })?;
    let status = response.status();
    let body = response.text().map_err(|error| {
        crate::error::CompileError::without_span(format!("failed to read authorisation session status: {error}"))
            .with_category(crate::error::CompileErrorCategory::Network)
            .with_source(error)
    })?;
    if status == reqwest::StatusCode::GONE {
        return Ok(RegistryAuthorisationSessionPollOutcome::Expired);
    }
    if !status.is_success() {
        return Err(crate::error::CompileError::without_span(format!(
            "browser authorisation session failed with HTTP {status}: {}",
            body.trim()
        ))
        .with_category(registry_http_error_category(status)));
    }
    let poll = serde_json::from_str::<RegistryAuthorisationSessionPollResponse>(&body).map_err(|error| {
        crate::error::CompileError::without_span(format!("registry returned an invalid authorisation status: {error}"))
            .with_category(crate::error::CompileErrorCategory::Network)
            .with_source(error)
    })?;
    Ok(RegistryAuthorisationSessionPollOutcome::State(poll))
}

fn registry_authorisation_status_removes_pending_key(status: &str) -> bool {
    matches!(status, "cancelled" | "expired")
}

fn resolve_registry_authorisation_session_poll(
    poll: RegistryAuthorisationSessionPollResponse,
    generated: &GeneratedRegistryKeyMaterial,
    namespace: &str,
) -> Result<Option<String>> {
    activate_registry_key_after_wallet_approval(&poll.status, poll.capability_key_id.as_deref(), &generated.key_id, || {
        store_registry_private_key(&generated.key_id, &generated.private_key_pkcs8)
    })?;
    match poll.status.as_str() {
        "pending" => Ok(None),
        "authorised" => {
            let key_id = poll
                .capability_key_id
                .ok_or_else(|| crate::error::CompileError::without_span("authorised session did not return a capability key"))?;
            eprintln!("Publishing authorisation confirmed; continuing with cellc.");
            Ok(Some(key_id))
        }
        "review_pending" => {
            let key_id = poll.capability_key_id.as_deref().ok_or_else(|| {
                crate::error::CompileError::without_span("review_pending session did not return a capability key")
                    .with_category(crate::error::CompileErrorCategory::Authentication)
            })?;
            Err(crate::error::CompileError::without_span(format!(
                "wallet authorisation succeeded, but namespace '{namespace}' is awaiting Registry review; rerun publish with --capability-key-id {key_id} after approval"
            ))
            .with_category(crate::error::CompileErrorCategory::Authentication))
        }
        status if registry_authorisation_status_removes_pending_key(status) => {
            remove_registry_private_key(&generated.key_id)?;
            Err(crate::error::CompileError::without_span(format!(
                "browser authorisation session was {status}; run `cellc publish --authorise` again"
            ))
            .with_category(crate::error::CompileErrorCategory::Authentication))
        }
        other => Err(crate::error::CompileError::without_span(format!(
            "registry returned unknown authorisation session status '{other}' (namespace status: {})",
            poll.namespace_status.as_deref().unwrap_or("unknown")
        ))
        .with_category(crate::error::CompileErrorCategory::Network)),
    }
}

fn activate_registry_key_after_wallet_approval<F>(
    status: &str,
    returned_key_id: Option<&str>,
    generated_key_id: &str,
    persist: F,
) -> Result<()>
where
    F: FnOnce() -> Result<()>,
{
    if !matches!(status, "authorised" | "review_pending") {
        return Ok(());
    }
    let Some(returned_key_id) = returned_key_id else {
        return Err(crate::error::CompileError::without_span(format!("{status} session did not return a publishing key"))
            .with_category(crate::error::CompileErrorCategory::Authentication));
    };
    if returned_key_id != generated_key_id {
        return Err(crate::error::CompileError::without_span(
            "registry approved a different publishing key than the one held locally",
        )
        .with_category(crate::error::CompileErrorCategory::Authentication));
    }
    persist()
}

fn authorise_registry_publish_key(api_base: &str, namespace: &str, name: &str, artifact_kind: &str, no_open: bool) -> Result<String> {
    let generated = generate_registry_key_material()?;
    let client = registry_http_client()?;
    let endpoint = format!("{}/v1/authorisation-sessions", api_base.trim_end_matches('/'));
    let response = client
        .post(&endpoint)
        .json(&RegistryAuthorisationSessionCreateRequest {
            capability_pubkey: generated.public_key.clone(),
            requested_scopes: vec![format!("publish:{namespace}/{name}")],
            artifact_kind: artifact_kind.to_string(),
            capability_expires_at: utc_timestamp_after_seconds(90 * 24 * 60 * 60),
            cli_version: crate::VERSION.to_string(),
        })
        .send()
        .map_err(|error| {
            crate::error::CompileError::without_span(format!("failed to create browser authorisation session: {error}"))
                .with_category(crate::error::CompileErrorCategory::Network)
                .with_source(error)
        })?;
    let status = response.status();
    let body = response.text().map_err(|error| {
        crate::error::CompileError::without_span(format!("failed to read browser authorisation session response: {error}"))
            .with_category(crate::error::CompileErrorCategory::Network)
            .with_source(error)
    })?;
    if !status.is_success() {
        return Err(crate::error::CompileError::without_span(format!(
            "registry refused browser authorisation session with HTTP {status}: {}",
            body.trim()
        ))
        .with_category(registry_http_error_category(status)));
    }
    let session: RegistryAuthorisationSessionCreateResponse = serde_json::from_str(&body).map_err(|error| {
        crate::error::CompileError::without_span(format!("registry returned an invalid authorisation session: {error}"))
            .with_category(crate::error::CompileErrorCategory::Network)
            .with_source(error)
    })?;
    validate_registry_authorisation_session(&session, api_base)?;
    if generated.key_id != registry_capability_key_id(&generated.public_key) {
        return Err(crate::error::CompileError::without_span(
            "generated capability key identity changed before browser authorisation",
        )
        .with_category(crate::error::CompileErrorCategory::Authentication));
    }
    store_pending_registry_private_key(&generated.key_id, &generated.private_key_pkcs8, &session.session_id, &session.expires_at)?;
    eprintln!("Authorise publishing {namespace}/{name} in your CKB wallet:");
    eprintln!("  {}", session.browser_url);
    eprintln!("Pending publishing key: {}", generated.key_id);
    if !no_open && let Err(error) = open_registry_authorisation_url(&session.browser_url) {
        eprintln!("Browser did not open automatically: {error}");
    }
    eprintln!("Waiting for wallet approval…");

    let poll_endpoint = format!("{}/v1/authorisation-sessions/{}", api_base.trim_end_matches('/'), session.session_id);
    let deadline = std::time::Instant::now() + Duration::from_secs(15 * 60);
    while std::time::Instant::now() < deadline {
        match fetch_registry_authorisation_session(&client, &poll_endpoint, &session.poll_token)? {
            RegistryAuthorisationSessionPollOutcome::Expired => {
                remove_registry_private_key(&generated.key_id)?;
                return Err(crate::error::CompileError::without_span(
                    "browser authorisation session expired before wallet approval; run `cellc publish --authorise` again",
                )
                .with_category(crate::error::CompileErrorCategory::Authentication));
            }
            RegistryAuthorisationSessionPollOutcome::State(poll) => {
                if let Some(key_id) = resolve_registry_authorisation_session_poll(poll, &generated, namespace)? {
                    return Ok(key_id);
                }
                std::thread::sleep(Duration::from_secs(2));
            }
        }
    }

    // The server may have committed wallet approval immediately before the local
    // deadline. One final authoritative read closes that race. A still-pending or
    // unreachable session keeps its pending key so a later CLI invocation can recover it.
    match fetch_registry_authorisation_session(&client, &poll_endpoint, &session.poll_token)? {
        RegistryAuthorisationSessionPollOutcome::Expired => {
            remove_registry_private_key(&generated.key_id)?;
            Err(crate::error::CompileError::without_span(
                "browser authorisation session expired before wallet approval; run `cellc publish --authorise` again",
            )
            .with_category(crate::error::CompileErrorCategory::Authentication))
        }
        RegistryAuthorisationSessionPollOutcome::State(poll) => {
            if let Some(key_id) = resolve_registry_authorisation_session_poll(poll, &generated, namespace)? {
                return Ok(key_id);
            }
            Err(crate::error::CompileError::without_span(format!(
                "browser authorisation is still pending; publishing key {} remains in the OS keychain for recovery",
                generated.key_id
            ))
            .with_category(crate::error::CompileErrorCategory::Authentication))
        }
    }
}

fn validate_registry_authorisation_session(session: &RegistryAuthorisationSessionCreateResponse, api_base: &str) -> Result<()> {
    if !session.session_id.starts_with("auth_")
        || session.session_id.len() != 37
        || !session.session_id[5..].bytes().all(|byte| byte.is_ascii_hexdigit())
        || !session.poll_token.starts_with("poll_")
        || session.poll_token.len() != 37
        || !session.poll_token[5..].bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(crate::error::CompileError::without_span("registry returned malformed authorisation credentials")
            .with_category(crate::error::CompileErrorCategory::Network));
    }
    let browser = reqwest::Url::parse(&session.browser_url).map_err(|error| {
        crate::error::CompileError::without_span(format!("registry returned an invalid browser URL: {error}"))
            .with_category(crate::error::CompileErrorCategory::Network)
    })?;
    let api = parse_registry_api_url(api_base)?;
    let browser_host = browser.host_str().unwrap_or_default();
    let fragment = browser.fragment().unwrap_or_default();
    let fragment_value = |name: &str| {
        fragment.split('&').find_map(|part| {
            let (key, value) = part.split_once('=')?;
            (key == name).then_some(value)
        })
    };
    let browser_session_id = fragment_value("authorisation_session");
    let browser_token = fragment_value("browser_token").unwrap_or_default();
    let loopback = browser_host.parse::<std::net::IpAddr>().is_ok_and(|address| address.is_loopback())
        || browser_host.eq_ignore_ascii_case("localhost");
    if (browser.scheme() != "https" && !(browser.scheme() == "http" && loopback))
        || !browser.username().is_empty()
        || browser.password().is_some()
        || browser.query().is_some()
        || browser_session_id != Some(session.session_id.as_str())
        || !browser_token.starts_with("browser_")
        || browser_token.len() != 40
        || !browser_token[8..].bytes().all(|byte| byte.is_ascii_hexdigit())
        || !browser.path().ends_with("/registry/submit")
        || (api.scheme() == "https" && browser.scheme() != "https")
    {
        return Err(crate::error::CompileError::without_span("registry returned an unsafe browser authorisation URL")
            .with_category(crate::error::CompileErrorCategory::Network));
    }
    Ok(())
}

fn open_registry_authorisation_url(url: &str) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    let status = std::process::Command::new("open").arg(url).status()?;
    #[cfg(target_os = "windows")]
    let status = std::process::Command::new("rundll32").args(["url.dll,FileProtocolHandler", url]).status()?;
    #[cfg(all(unix, not(target_os = "macos")))]
    let status = std::process::Command::new("xdg-open").arg(url).status()?;
    #[cfg(not(any(unix, windows)))]
    return Err(std::io::Error::other("automatic browser opening is unsupported on this platform"));
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other("browser launcher returned a failure status"))
    }
}

fn submit_registry_publish_request_with_retry(
    client: &reqwest::blocking::Client,
    endpoint: &str,
    request: &crate::package::registry::RegistryPublishRequest,
    idempotency_key: &str,
) -> Result<reqwest::blocking::Response> {
    let mut transport_error = None;
    for attempt in 0..2 {
        let response = client.post(endpoint).header("Idempotency-Key", idempotency_key).json(request).send();
        match response {
            Ok(response) => {
                if attempt == 0 && is_retryable_registry_status(response.status()) {
                    std::thread::sleep(Duration::from_millis(500));
                    continue;
                }
                return Ok(response);
            }
            Err(error) if attempt == 0 => {
                transport_error = Some(error);
                std::thread::sleep(Duration::from_millis(500));
            }
            Err(error) => {
                return Err(crate::error::CompileError::without_span(format!(
                    "failed to submit registry publish request to '{}': {}",
                    endpoint, error
                ))
                .with_category(crate::error::CompileErrorCategory::Network)
                .with_source(error));
            }
        }
    }
    let message = transport_error
        .map(|error| error.to_string())
        .unwrap_or_else(|| "registry publish request did not produce a response".to_string());
    Err(crate::error::CompileError::without_span(format!("failed to submit registry publish request to '{}': {}", endpoint, message))
        .with_category(crate::error::CompileErrorCategory::Network))
}

fn is_retryable_registry_status(status: reqwest::StatusCode) -> bool {
    matches!(
        status,
        reqwest::StatusCode::REQUEST_TIMEOUT
            | reqwest::StatusCode::BAD_GATEWAY
            | reqwest::StatusCode::SERVICE_UNAVAILABLE
            | reqwest::StatusCode::GATEWAY_TIMEOUT
            | reqwest::StatusCode::INTERNAL_SERVER_ERROR
    )
}

fn registry_http_error_category(status: reqwest::StatusCode) -> crate::error::CompileErrorCategory {
    if matches!(status, reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN) {
        crate::error::CompileErrorCategory::Authentication
    } else {
        crate::error::CompileErrorCategory::Network
    }
}

fn submit_registry_json_request(
    endpoint: &str,
    body: &serde_json::Value,
    success_label: &str,
    json_output: bool,
) -> Result<serde_json::Value> {
    let client = registry_http_client()?;
    let response = client.post(endpoint).json(body).send().map_err(|error| {
        crate::error::CompileError::without_span(format!("failed to submit registry request to '{}': {}", endpoint, error))
            .with_category(crate::error::CompileErrorCategory::Network)
            .with_source(error)
    })?;
    let status = response.status();
    let response_body = response.text().map_err(|error| {
        crate::error::CompileError::without_span(format!("failed to read registry response from '{}': {}", endpoint, error))
            .with_category(crate::error::CompileErrorCategory::Network)
            .with_source(error)
    })?;
    if !status.is_success() {
        return Err(crate::error::CompileError::without_span(format!(
            "registry request failed with HTTP {}: {}",
            status,
            response_body.trim()
        ))
        .with_category(registry_http_error_category(status)));
    }
    let parsed =
        serde_json::from_str::<serde_json::Value>(&response_body).unwrap_or_else(|_| serde_json::json!({ "response": response_body }));
    if json_output {
        print_json(&parsed)?;
    } else {
        println!("{}", success_label.green());
        if let Some(request_id) = parsed.get("request_id").and_then(serde_json::Value::as_str) {
            println!("  Request id: {}", request_id);
        }
    }
    Ok(parsed)
}

fn compile_cli_input(input: Option<&PathBuf>, options: CompileOptions) -> Result<crate::CompileResult> {
    let input_path = input.cloned().unwrap_or_else(|| PathBuf::from("."));
    let input = Utf8Path::from_path(&input_path)
        .ok_or_else(|| crate::error::CompileError::without_span(format!("path '{}' is not valid UTF-8", input_path.display())))?;
    compile_path(input, options)
}

fn compile_failure_diagnostics(input: &Utf8Path, options: CompileOptions, fallback: CompileError) -> Vec<CompileError> {
    if fallback.category != crate::error::CompileErrorCategory::Compilation
        || fallback.code.as_deref().is_some_and(|code| code.starts_with("CG"))
    {
        return vec![fallback];
    }
    let report = compile_path_metadata_with_diagnostics(input, options);
    if report.diagnostics.is_empty() {
        vec![fallback]
    } else {
        report.diagnostics
    }
}

fn diagnostics_to_error(diagnostics: &[CompileError]) -> CompileError {
    match diagnostics {
        [] => CompileError::without_span("compile failed"),
        [diagnostic] => diagnostic.clone(),
        _ => {
            CompileError::without_span(format!("aborting due to {} diagnostics", diagnostics.len())).with_related(diagnostics.to_vec())
        }
    }
}

fn read_metadata_json(path: &Path) -> Result<CompileMetadata> {
    let bytes = std::fs::read(path).map_err(|error| {
        crate::error::CompileError::without_span(format!("failed to read metadata '{}': {}", path.display(), error))
            .with_category(crate::error::CompileErrorCategory::Io)
            .with_source(error)
    })?;
    serde_json::from_slice(&bytes)
        .map_err(|error| crate::error::CompileError::without_span(format!("failed to parse metadata '{}': {}", path.display(), error)))
}

fn read_or_compile_interface(path: &Path) -> Result<crate::interface::PackageInterface> {
    if path.extension().and_then(|extension| extension.to_str()) == Some("json") {
        let bytes = std::fs::read(path).map_err(|error| {
            crate::error::CompileError::without_span(format!("failed to read interface '{}': {error}", path.display()))
        })?;
        let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|error| {
            crate::error::CompileError::without_span(format!("failed to parse interface '{}': {error}", path.display()))
        })?;
        let interface_value = value.get("interface").cloned().unwrap_or(value);
        return serde_json::from_value(interface_value).map_err(|error| {
            crate::error::CompileError::without_span(format!("invalid public interface '{}': {error}", path.display()))
        });
    }
    let input = Utf8Path::from_path(path)
        .ok_or_else(|| crate::error::CompileError::without_span(format!("path '{}' is not valid UTF-8", path.display())))?;
    Ok(compile_path(input, CompileOptions::default())?.metadata.public_interface)
}

fn read_json_value(path: &Path) -> Result<serde_json::Value> {
    let bytes = std::fs::read(path).map_err(|error| {
        crate::error::CompileError::without_span(format!("failed to read JSON '{}': {}", path.display(), error))
            .with_category(crate::error::CompileErrorCategory::Io)
            .with_source(error)
    })?;
    serde_json::from_slice(&bytes)
        .map_err(|error| crate::error::CompileError::without_span(format!("failed to parse JSON '{}': {}", path.display(), error)))
}

fn print_json(value: &serde_json::Value) -> Result<()> {
    let json = serde_json::to_string_pretty(value).map_err(|error| {
        crate::error::CompileError::without_span(format!("failed to serialize JSON: {}", error))
            .with_category(crate::error::CompileErrorCategory::Internal)
            .with_source(error)
    })?;
    println!("{}", json);
    Ok(())
}

fn ckb_blake2b_file_hash(path: &Path) -> Result<Option<String>> {
    if !path.is_file() {
        return Ok(None);
    }
    let bytes = std::fs::read(path)
        .map_err(|error| crate::error::CompileError::without_span(format!("failed to read '{}': {}", path.display(), error)))?;
    Ok(Some(crate::hex_encode(&crate::ckb_blake2b256(&bytes))))
}

fn json_pointer_str<'a>(value: &'a serde_json::Value, pointer: &str) -> Option<&'a str> {
    value.pointer(pointer).and_then(serde_json::Value::as_str)
}

fn json_pointer_bool(value: &serde_json::Value, pointer: &str) -> bool {
    value.pointer(pointer).and_then(serde_json::Value::as_bool).unwrap_or(false)
}

fn novaseal_gate_status<'a>(report: &'a serde_json::Value, gate_name: &str) -> Option<&'a str> {
    report.get("gates")?.as_array()?.iter().find_map(|gate| {
        let name = gate.get("name").and_then(serde_json::Value::as_str)?;
        if name == gate_name {
            gate.get("status").and_then(serde_json::Value::as_str)
        } else {
            None
        }
    })
}

fn novaseal_certification_failure_message(summary: &serde_json::Value) -> String {
    let reason = summary.get("failure_reason").unwrap_or(&serde_json::Value::Null);
    if let Some(message) = json_pointer_str(reason, "/message") {
        return message.to_string();
    }
    if let Some(message) = reason.as_str() {
        return message.to_string();
    }
    if !reason.is_null() {
        return serde_json::to_string(reason).unwrap_or_else(|_| "certification failed".to_string());
    }
    "certification failed".to_string()
}

fn novaseal_failed_dimensions(plugin_report: &serde_json::Value, v1_readiness: &serde_json::Value) -> serde_json::Value {
    let mut seen = BTreeSet::new();
    let mut dimensions = Vec::new();
    for source in [plugin_report.get("failed_dimensions"), v1_readiness.get("failed_dimensions")] {
        let Some(items) = source.and_then(serde_json::Value::as_array) else {
            continue;
        };
        for item in items {
            let Some(name) = item.as_str() else {
                continue;
            };
            if seen.insert(name.to_string()) {
                dimensions.push(serde_json::Value::String(name.to_string()));
            }
        }
    }
    serde_json::Value::Array(dimensions)
}

fn novaseal_failed_dimension_matches(failed_dimensions: &serde_json::Value, expected: &[&str]) -> bool {
    failed_dimensions.as_array().is_some_and(|dimensions| {
        dimensions.iter().filter_map(serde_json::Value::as_str).any(|dimension| expected.contains(&dimension))
    })
}

#[allow(clippy::too_many_arguments)]
fn novaseal_certification_summary(
    plugin_report: &serde_json::Value,
    repo_root: &Path,
    plugin_report_path: &Path,
    implementation_path: &Path,
    report_generated: bool,
    require_production: bool,
) -> Result<serde_json::Value> {
    let plugin_report_hash = ckb_blake2b_file_hash(plugin_report_path)?.ok_or_else(|| {
        crate::error::CompileError::without_span(format!(
            "NovaSeal plugin report '{}' is not a regular file",
            plugin_report_path.display()
        ))
    })?;
    let implementation_hash = ckb_blake2b_file_hash(implementation_path)?;
    let profile_certification = plugin_report.get("profile_certification").unwrap_or(&serde_json::Value::Null);
    let v1_readiness = plugin_report.get("v1_readiness").unwrap_or(&serde_json::Value::Null);

    let mut checks = vec![
        ("plugin_report_schema", json_pointer_str(plugin_report, "/schema") == Some(NOVASEAL_PLUGIN_REPORT_SCHEMA)),
        (
            "profile_certification_schema",
            json_pointer_str(profile_certification, "/schema") == Some(NOVASEAL_PROFILE_CERTIFICATION_SCHEMA),
        ),
        ("profile_id", json_pointer_str(profile_certification, "/profile") == Some(NOVASEAL_AGREEMENT_PROFILE)),
        ("canonical_target", json_pointer_str(profile_certification, "/conforms_to") == Some(NOVASEAL_CANONICAL_SCHEMA)),
        ("profile_certification_passed", json_pointer_str(profile_certification, "/status") == Some("passed")),
        ("public_ecosystem_gate_passed", novaseal_gate_status(plugin_report, NOVASEAL_PROFILE_CERTIFICATION_GATE) == Some("passed")),
        ("local_production_prep_ready", json_pointer_bool(plugin_report, "/local_production_prep_ready")),
    ];
    if !v1_readiness.is_null() {
        checks.push(("v1_readiness_local_ready", json_pointer_bool(v1_readiness, "/local_v1_ready")));
    }

    let production_statement_eligible = plugin_report
        .pointer("/production_statement_eligible")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or_else(|| json_pointer_bool(profile_certification, "/production_statement_eligible"));

    if require_production {
        checks.push(("production_ready", json_pointer_bool(plugin_report, "/production_ready")));
        checks.push(("production_statement_eligible", production_statement_eligible));
    }

    let checks_json =
        checks.iter().map(|(name, passed)| ((*name).to_string(), serde_json::Value::Bool(*passed))).collect::<serde_json::Map<_, _>>();
    let failed_checks: Vec<serde_json::Value> =
        checks.iter().filter(|(_, passed)| !*passed).map(|(name, _)| serde_json::Value::String((*name).to_string())).collect();
    let passed = failed_checks.is_empty();
    let external_blockers = plugin_report
        .get("external_blockers")
        .cloned()
        .or_else(|| v1_readiness.get("external_blockers").cloned())
        .or_else(|| profile_certification.get("production_statement_blockers").cloned())
        .unwrap_or_else(|| serde_json::Value::Array(Vec::new()));
    let failed_dimensions = novaseal_failed_dimensions(plugin_report, v1_readiness);
    let planned_missing =
        v1_readiness.pointer("/planned_profile_matrix/missing").cloned().unwrap_or_else(|| serde_json::Value::Array(Vec::new()));
    let planned_missing_non_empty = planned_missing.as_array().is_some_and(|items| !items.is_empty());
    let external_blockers_non_empty = external_blockers.as_array().is_some_and(|items| !items.is_empty());
    let failed_local_v1_dimension = novaseal_failed_dimension_matches(&failed_dimensions, NOVASEAL_LOCAL_V1_DIMENSIONS);
    let failed_external_or_endpoint_dimension = novaseal_failed_dimension_matches(&failed_dimensions, NOVASEAL_EXTERNAL_V1_DIMENSIONS);
    let certification_level = json_pointer_str(profile_certification, "/certification_level").unwrap_or("unknown");

    let failure_reason = if passed {
        serde_json::Value::Null
    } else if !v1_readiness.is_null() && !json_pointer_bool(v1_readiness, "/local_v1_ready") && planned_missing_non_empty {
        serde_json::json!({
            "message": "NovaSeal V1 readiness requires remaining planned profiles and business scenarios",
            "v1_status": json_pointer_str(v1_readiness, "/status"),
            "missing": planned_missing,
            "failed_dimensions": failed_dimensions.clone(),
            "external_blockers": external_blockers.clone(),
            "failed_checks": failed_checks,
        })
    } else if !v1_readiness.is_null() && !json_pointer_bool(v1_readiness, "/local_v1_ready") && failed_local_v1_dimension {
        serde_json::json!({
            "message": "NovaSeal V1 readiness requires fresh local evidence reports",
            "remediation": [
                "rerun live devnet reports for core, Agreement, and planned profiles after source or report changes",
                "rerun NovaSeal wallet, operator fixture, service-builder, BTC SPV adapter, external attestation adapter, BIP340 TCB review, and handoff bundle generators"
            ],
            "v1_status": json_pointer_str(v1_readiness, "/status"),
            "missing": planned_missing,
            "failed_dimensions": failed_dimensions.clone(),
            "external_blockers": external_blockers.clone(),
            "failed_checks": failed_checks,
        })
    } else if !v1_readiness.is_null()
        && !json_pointer_bool(v1_readiness, "/local_v1_ready")
        && (external_blockers_non_empty || failed_external_or_endpoint_dimension)
    {
        serde_json::json!({
            "message": "NovaSeal V1 readiness requires external production evidence and endpoint acceptance",
            "v1_status": json_pointer_str(v1_readiness, "/status"),
            "missing": planned_missing,
            "failed_dimensions": failed_dimensions.clone(),
            "external_blockers": external_blockers.clone(),
            "failed_checks": failed_checks,
        })
    } else if require_production && json_pointer_bool(plugin_report, "/local_production_prep_ready") {
        serde_json::json!({
            "message": "NovaSeal production certification requires remaining external attestations",
            "external_blockers": external_blockers.clone(),
            "failed_dimensions": failed_dimensions.clone(),
            "failed_checks": failed_checks,
        })
    } else {
        serde_json::json!({
            "message": "NovaSeal profile certification failed deterministic compiler checks",
            "failed_dimensions": failed_dimensions.clone(),
            "external_blockers": external_blockers.clone(),
            "failed_checks": failed_checks,
        })
    };

    Ok(serde_json::json!({
        "schema": NOVASEAL_CERTIFICATION_REPORT_SCHEMA,
        "status": if passed { "passed" } else { "failed" },
        "plugin": {
            "id": NOVASEAL_CERTIFICATION_PLUGIN,
            "kind": "compiler-builtin-rust",
            "implementation": super::novaseal_certification::IMPLEMENTATION_ID,
            "implementation_path": implementation_path.display().to_string(),
            "implementation_hash_algorithm": "ckb_blake2b_256",
            "implementation_hash": implementation_hash,
            "report_generated": report_generated,
        },
        "plugin_report": {
            "path": plugin_report_path.display().to_string(),
            "schema": json_pointer_str(plugin_report, "/schema"),
            "hash_algorithm": "ckb_blake2b_256",
            "hash": plugin_report_hash,
            "status": json_pointer_str(plugin_report, "/status"),
            "production_ready": json_pointer_bool(plugin_report, "/production_ready"),
            "production_gates_passed": json_pointer_bool(plugin_report, "/production_gates_passed"),
            "local_production_prep_ready": json_pointer_bool(plugin_report, "/local_production_prep_ready"),
            "v1_status": json_pointer_str(v1_readiness, "/status"),
            "local_v1_ready": json_pointer_bool(v1_readiness, "/local_v1_ready"),
        },
        "profile": NOVASEAL_AGREEMENT_PROFILE,
        "conforms_to": NOVASEAL_CANONICAL_SCHEMA,
        "certification_level": certification_level,
        "production_statement_eligible": production_statement_eligible,
        "failed_dimensions": failed_dimensions,
        "external_blockers": external_blockers,
        "require_production": require_production,
        "repo_root": repo_root.display().to_string(),
        "checks": checks_json,
        "failure_reason": failure_reason,
    }))
}

fn write_or_print_json(output: Option<&PathBuf>, value: &serde_json::Value, json_stdout: bool, label: &str) -> Result<()> {
    let json = serde_json::to_string_pretty(value)
        .map_err(|error| crate::error::CompileError::without_span(format!("failed to serialize JSON: {}", error)))?;
    if let Some(output_path) = output {
        if let Some(parent) = output_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(output_path, json)?;
        if json_stdout {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "status": "ok",
                    "output": output_path.display().to_string(),
                }))
                .map_err(|error| crate::error::CompileError::without_span(format!("failed to serialize JSON: {}", error)))?
            );
        } else {
            println!("{}", label.green());
            println!("  Output: {}", output_path.display());
        }
    } else {
        println!("{}", json);
    }
    Ok(())
}

fn print_or_text_json(json: bool, value: &serde_json::Value, label: &str) -> Result<()> {
    if json {
        print_json(value)
    } else {
        println!("{}: {}", label, value["status"].as_str().unwrap_or("ok"));
        Ok(())
    }
}

fn selected_builder_actions<'a>(metadata: &'a CompileMetadata, action_name: Option<&str>) -> Result<Vec<&'a crate::ActionMetadata>> {
    if let Some(policy) = &metadata.runtime.policy_artifact {
        policy.validate()?;
        let variants = policy
            .declaration
            .actions
            .iter()
            .filter(|variant| action_name.is_none_or(|name| variant.action == name))
            .map(|variant| {
                let matches = metadata.actions.iter().filter(|action| action.name == variant.action).collect::<Vec<_>>();
                if matches.len() != 1 {
                    return Err(CompileError::without_span(format!("policy action '{}' must resolve exactly once", variant.action)));
                }
                Ok(matches[0])
            })
            .collect::<Result<Vec<_>>>()?;
        if variants.is_empty() {
            return Err(CompileError::without_span(format!(
                "action '{}' is not an exported variant of policy '{}'",
                action_name.unwrap_or(""),
                policy.declaration.name
            )));
        }
        return Ok(variants);
    }
    if let Some(action_name) = action_name {
        let action =
            metadata.actions.iter().find(|action| action.name == action_name).ok_or_else(|| {
                crate::error::CompileError::without_span(format!("action '{}' was not found in metadata", action_name))
            })?;
        return Ok(vec![action]);
    }

    if metadata.actions.is_empty() {
        return Err(crate::error::CompileError::without_span("no actions found in metadata for generated builder"));
    }

    Ok(metadata.actions.iter().collect())
}

fn policy_entry_witness(args: &EntryWitnessArgs, input: &Utf8Path) -> Result<()> {
    let artifact_name = args.artifact.as_deref().expect("policy branch selected");
    if args.lock.is_some() {
        return Err(CompileError::without_span("entry-witness --artifact supports Type policies, not --lock"));
    }
    let action_name =
        args.action.as_deref().ok_or_else(|| CompileError::without_span("entry-witness --artifact requires --action"))?;
    let hash = args.script_hash.as_deref().ok_or_else(|| {
        CompileError::without_span("entry-witness --artifact requires --script-hash with the full deployed Script hash")
    })?;
    let script_hash: [u8; 32] = decode_hex_arg("script-hash", hash, Some(32))?.try_into().expect("validated full Script hash");
    let metadata = crate::artifact::compile_path_artifact_metadata(
        input,
        CompileOptions {
            edition: crate::CURRENT_EDITION,
            target: args.target.clone(),
            target_profile: args.target_profile.clone(),
            ..Default::default()
        },
        artifact_name,
    )?;
    let selected = selected_builder_actions(&metadata, Some(action_name))?;
    let action = selected[0];
    let runtime_bound = crate::runtime_bound_param_names(&action.params);
    let params =
        action.params.iter().filter(|param| crate::param_consumes_entry_witness_payload(param, &runtime_bound)).collect::<Vec<_>>();
    if args.args.len() != params.len() {
        return Err(CompileError::without_span(format!(
            "policy action '{action_name}' expects {} witness payload arg(s), got {}",
            params.len(),
            args.args.len()
        )));
    }
    let values =
        params.iter().zip(&args.args).map(|(param, value)| parse_entry_witness_arg(param, value)).collect::<Result<Vec<_>>>()?;
    let record = crate::artifact::encode_policy_action_record(&metadata, &script_hash, action_name, &values)?;
    let bundle = crate::policy_witness::encode_policy_witness_bundle(std::slice::from_ref(&record))
        .map_err(|error| CompileError::without_span(format!("failed to encode policy witness: {error}")))?;
    if let Some(path) = &args.output {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, &bundle)?;
    }
    let witness_hex = crate::hex_encode(&bundle);
    CommandOutcome {
        machine: serde_json::json!({
            "status": "ok",
            "abi": crate::policy_witness::POLICY_WITNESS_ABI,
            "placement_abi": crate::artifact::POLICY_WITNESS_PLACEMENT_ABI,
            "witness_args_field": crate::artifact::POLICY_WITNESS_PLACEMENT_FIELD,
            "witness_source": crate::artifact::POLICY_WITNESS_PLACEMENT_SOURCE,
            "policy_artifact": artifact_name,
            "entry_kind": "type-policy-action",
            "entry": action_name,
            "role": "type",
            "tag": record.tag,
            "script_hash": crate::hex_encode(&script_hash),
            "script_hash_is_authentication": false,
            "placement_performed": false,
            "requires_shared_witness_aggregation": true,
            "requires_pre_signing_placement": true,
            "raw_v1_compatible": false,
            "witness_hex": witness_hex,
            "witness_size_bytes": bundle.len(),
            "payload_args": values.len(),
            "payload_params": params.iter().map(|param| &param.name).collect::<Vec<_>>(),
            "output": args.output.as_ref().map(|path| path.display().to_string()),
        }),
        human_lines: vec![
            format!("Policy witness encoded: {artifact_name} / {action_name} (tag {})", record.tag),
            "Full Script hash is caller-supplied, not authentication; aggregate and place before signing.".to_string(),
            witness_hex,
        ],
    }
    .emit(args.json)
}

fn read_lockfile_path(path: &Path) -> Result<Lockfile> {
    let content = std::fs::read_to_string(path).map_err(|error| {
        crate::error::CompileError::without_span(format!("failed to read lockfile '{}': {}", path.display(), error))
    })?;
    let lockfile: Lockfile = toml::from_str(&content).map_err(|error| {
        crate::error::CompileError::without_span(format!("failed to parse lockfile '{}': {}", path.display(), error))
    })?;
    lockfile.validate_schema()?;
    Ok(lockfile)
}

fn read_deployed_manifest_path(path: &Path) -> Result<crate::package::DeployedManifest> {
    let content = std::fs::read_to_string(path).map_err(|error| {
        crate::error::CompileError::without_span(format!("failed to read deployed manifest '{}': {}", path.display(), error))
    })?;
    let manifest: crate::package::DeployedManifest = toml::from_str(&content).map_err(|error| {
        crate::error::CompileError::without_span(format!("failed to parse deployed manifest '{}': {}", path.display(), error))
    })?;
    manifest.validate_schema()?;
    Ok(manifest)
}

fn verify_builder_lockfile_identity(
    lockfile_path: &Path,
    metadata: &CompileMetadata,
    metadata_hash: &str,
) -> Result<serde_json::Value> {
    let lockfile = read_lockfile_path(lockfile_path)?;
    let expected_build = locked_build_info_from_metadata(metadata)?;
    let mut violations = Vec::new();
    if lockfile.package.edition != metadata.edition {
        violations.push(format!(
            "edition mismatch: Cell.lock package has '{}' but metadata has '{}'",
            lockfile.package.edition, metadata.edition
        ));
    }

    let locked_compiler_source_hash = lockfile.package.compiler_source_hash.as_ref().or(lockfile.package.source_hash.as_ref());
    let locked_source_label = if lockfile.package.compiler_source_hash.is_some() { "compiler_source_hash" } else { "source_hash" };
    match (locked_compiler_source_hash, &metadata.source_hash) {
        (Some(locked), Some(actual)) if locked == actual => {}
        (Some(locked), Some(actual)) => violations
            .push(format!("{} mismatch: Cell.lock has '{}', metadata source_hash is '{}'", locked_source_label, locked, actual)),
        (None, _) => violations.push("Cell.lock [package] has no compiler_source_hash or source_hash".to_string()),
        (_, None) => violations.push("metadata has no source_hash".to_string()),
    }

    match &lockfile.package_build {
        Some(build) => {
            push_missing_locked_build_identity("Cell.lock [package.build]", build, &mut violations);
            if build.edition != metadata.edition {
                violations.push(format!(
                    "edition mismatch: Cell.lock build has '{}' but metadata has '{}'",
                    build.edition, metadata.edition
                ));
            }
            if build.compatibility_profile_hash != expected_build.compatibility_profile_hash {
                violations.push(format!(
                    "compatibility_profile_hash mismatch: Cell.lock has '{}', metadata has '{}'",
                    build.compatibility_profile_hash, expected_build.compatibility_profile_hash
                ));
            }
            compare_builder_identity_field(
                "compiler_version",
                &build.compiler_version,
                &expected_build.compiler_version,
                &mut violations,
            );
            compare_builder_identity_field("target_profile", &build.target_profile, &expected_build.target_profile, &mut violations);
            compare_builder_identity_field("artifact_hash", &build.artifact_hash, &expected_build.artifact_hash, &mut violations);
            compare_builder_identity_field("metadata_hash", &build.metadata_hash, &Some(metadata_hash.to_string()), &mut violations);
            compare_builder_identity_field("schema_hash", &build.schema_hash, &expected_build.schema_hash, &mut violations);
            compare_builder_identity_field(
                "cell_data_codec_manifest_hash",
                &build.cell_data_codec_manifest_hash,
                &expected_build.cell_data_codec_manifest_hash,
                &mut violations,
            );
            compare_builder_identity_field("abi_hash", &build.abi_hash, &expected_build.abi_hash, &mut violations);
            compare_builder_identity_field(
                "constraints_hash",
                &build.constraints_hash,
                &expected_build.constraints_hash,
                &mut violations,
            );
        }
        None => violations.push("Cell.lock has no [package.build]".to_string()),
    }

    if !violations.is_empty() {
        return Err(crate::error::CompileError::without_span(format!(
            "generated builder identity verification failed: {}",
            violations.join("; ")
        )));
    }

    Ok(serde_json::json!({
        "schema": "cellscript-builder-locked-identity-v0.20",
        "package": lockfile.package,
        "build": lockfile.package_build,
        "verified_fields": [
            locked_source_label,
            "edition",
            "compatibility_profile_hash",
            "compiler_version",
            "target_profile",
            "artifact_hash",
            "metadata_hash",
            "schema_hash",
            "cell_data_codec_manifest_hash",
            "abi_hash",
            "constraints_hash"
        ]
    }))
}

fn verify_builder_deployment_identity(
    lockfile_path: &Path,
    deployed_path: &Path,
    metadata: &CompileMetadata,
    metadata_hash: &str,
    network_filter: Option<&str>,
) -> Result<serde_json::Value> {
    let lockfile = read_lockfile_path(lockfile_path)?;
    let deployed = read_deployed_manifest_path(deployed_path)?;
    let expected_build = locked_build_info_from_metadata(metadata)?;
    let mut violations = Vec::new();
    for (label, edition) in [("Cell.lock package", lockfile.package.edition), ("Deployed.toml package", deployed.package.edition)] {
        if edition != metadata.edition {
            violations.push(format!("edition mismatch: {} has '{}' but metadata has '{}'", label, edition, metadata.edition));
        }
    }

    match (&lockfile.package.source_hash, &deployed.package.source_hash) {
        (Some(locked), Some(deployed_hash)) if locked == deployed_hash => {}
        (Some(locked), Some(deployed_hash)) => {
            violations.push(format!("source_hash mismatch: Cell.lock has '{}', Deployed.toml has '{}'", locked, deployed_hash))
        }
        (None, _) => violations.push("Cell.lock [package] has no source_hash".to_string()),
        (_, None) => violations.push("Deployed.toml [package] has no source_hash".to_string()),
    }

    let locked_compiler_source_hash = lockfile.package.compiler_source_hash.as_ref().or(lockfile.package.source_hash.as_ref());
    match (locked_compiler_source_hash, &metadata.source_hash) {
        (Some(locked), Some(actual)) if locked == actual => {}
        (Some(locked), Some(actual)) => {
            violations.push(format!("compiler_source_hash mismatch: Cell.lock has '{}', metadata source_hash is '{}'", locked, actual))
        }
        (None, _) => violations.push("Cell.lock [package] has no compiler_source_hash or source_hash".to_string()),
        (_, None) => violations.push("metadata has no source_hash".to_string()),
    }

    match &deployed.build {
        Some(build) => {
            push_missing_deployed_build_identity("Deployed.toml [build]", build, &mut violations);
            if build.edition != metadata.edition {
                violations.push(format!(
                    "edition mismatch: Deployed.toml build has '{}' but metadata has '{}'",
                    build.edition, metadata.edition
                ));
            }
            if build.compatibility_profile_hash != expected_build.compatibility_profile_hash {
                violations.push(format!(
                    "compatibility_profile_hash mismatch: Deployed.toml has '{}', metadata has '{}'",
                    build.compatibility_profile_hash, expected_build.compatibility_profile_hash
                ));
            }
            compare_builder_deployed_field(
                "compiler_version",
                &build.compiler_version,
                &expected_build.compiler_version,
                &mut violations,
            );
            compare_builder_deployed_field("artifact_hash", &build.artifact_hash, &expected_build.artifact_hash, &mut violations);
            compare_builder_deployed_field("metadata_hash", &build.metadata_hash, &Some(metadata_hash.to_string()), &mut violations);
            compare_builder_deployed_field("schema_hash", &build.schema_hash, &expected_build.schema_hash, &mut violations);
            compare_builder_deployed_field(
                "cell_data_codec_manifest_hash",
                &build.cell_data_codec_manifest_hash,
                &expected_build.cell_data_codec_manifest_hash,
                &mut violations,
            );
            compare_builder_deployed_field("abi_hash", &build.abi_hash, &expected_build.abi_hash, &mut violations);
            compare_builder_deployed_field(
                "constraints_hash",
                &build.constraints_hash,
                &expected_build.constraints_hash,
                &mut violations,
            );
        }
        None => violations.push("Deployed.toml has no [build]".to_string()),
    }

    let mut verified_deployments = Vec::new();
    for deployment in &deployed.deployments {
        if network_filter.is_some_and(|network| network != deployment.network) {
            continue;
        }
        push_deployment_status_violation(deployment, &mut violations);
        if deployment.edition != metadata.edition {
            violations.push(format!(
                "edition mismatch for network '{}': deployment has '{}' but metadata has '{}'",
                deployment.network, deployment.edition, metadata.edition
            ));
        }
        if deployment.compatibility_profile_hash != expected_build.compatibility_profile_hash {
            violations.push(format!(
                "compatibility_profile_hash mismatch for network '{}': Deployed.toml has '{}', metadata has '{}'",
                deployment.network, deployment.compatibility_profile_hash, expected_build.compatibility_profile_hash
            ));
        }
        compare_builder_deployment_record_field(
            "artifact_hash",
            &deployment.artifact_hash,
            &expected_build.artifact_hash,
            &deployment.network,
            &mut violations,
        );
        compare_builder_deployment_record_field(
            "metadata_hash",
            &deployment.metadata_hash,
            &Some(metadata_hash.to_string()),
            &deployment.network,
            &mut violations,
        );
        compare_builder_deployment_record_field(
            "schema_hash",
            &deployment.schema_hash,
            &expected_build.schema_hash,
            &deployment.network,
            &mut violations,
        );
        compare_builder_deployment_record_field(
            "cell_data_codec_manifest_hash",
            &deployment.cell_data_codec_manifest_hash,
            &expected_build.cell_data_codec_manifest_hash,
            &deployment.network,
            &mut violations,
        );
        compare_builder_deployment_record_field(
            "abi_hash",
            &deployment.abi_hash,
            &expected_build.abi_hash,
            &deployment.network,
            &mut violations,
        );
        compare_builder_deployment_record_field(
            "constraints_hash",
            &deployment.constraints_hash,
            &expected_build.constraints_hash,
            &deployment.network,
            &mut violations,
        );
        compare_builder_deployment_record_field(
            "compiler_version",
            &deployment.compiler_version,
            &expected_build.compiler_version,
            &deployment.network,
            &mut violations,
        );

        match lockfile.deployment.get(&deployment.network) {
            Some(deployment_ref) => {
                compare_required_deployment_ref_field(
                    "code_hash",
                    deployment_ref.code_hash.as_deref(),
                    &deployment.code_hash,
                    &deployment.network,
                    &mut violations,
                );
                compare_required_deployment_ref_field(
                    "out_point",
                    deployment_ref.out_point.as_deref(),
                    &deployment.out_point,
                    &deployment.network,
                    &mut violations,
                );
                compare_required_deployment_ref_field(
                    "data_hash",
                    deployment_ref.data_hash.as_deref(),
                    &deployment.data_hash,
                    &deployment.network,
                    &mut violations,
                );
                if !deployment_ref.record.is_empty() {
                    let chain_record = format!("{}:{}", deployment.chain_id, deployment.out_point);
                    let network_record = format!("{}:{}", deployment.network, deployment.out_point);
                    if deployment_ref.record != deployment.out_point
                        && deployment_ref.record != chain_record
                        && deployment_ref.record != network_record
                    {
                        violations.push(format!(
                            "deployment record mismatch for network '{}': Cell.lock has '{}', Deployed.toml out_point is '{}'",
                            deployment.network, deployment_ref.record, deployment.out_point
                        ));
                    }
                } else {
                    violations.push(format!("deployment ref for network '{}' has empty record", deployment.network));
                }
            }
            None => violations.push(format!("deployment for network '{}' is missing from Cell.lock", deployment.network)),
        }

        verified_deployments.push(deployment);
    }

    if verified_deployments.is_empty() {
        violations.push(match network_filter {
            Some(network) => format!("no deployment record found for requested builder network '{}'", network),
            None => "no deployment records found for generated builder".to_string(),
        });
    }

    if !violations.is_empty() {
        return Err(crate::error::CompileError::without_span(format!(
            "generated builder deployment identity verification failed: {}",
            violations.join("; ")
        )));
    }

    Ok(serde_json::json!({
        "schema": "cellscript-builder-deployment-identity-v0.20",
        "package": deployed.package.clone(),
        "build": deployed.build.clone(),
        "network": network_filter,
        "deployments": verified_deployments,
        "verified_fields": [
            "source_hash",
            "compiler_source_hash",
            "edition",
            "compatibility_profile_hash",
            "compiler_version",
            "artifact_hash",
            "metadata_hash",
            "schema_hash",
            "cell_data_codec_manifest_hash",
            "abi_hash",
            "constraints_hash",
            "code_hash",
            "out_point",
            "data_hash",
            "deployment_status"
        ]
    }))
}

fn compare_builder_identity_field(
    field: &str,
    locked_value: &Option<String>,
    metadata_value: &Option<String>,
    violations: &mut Vec<String>,
) {
    match (locked_value, metadata_value) {
        (Some(locked), Some(actual)) if locked == actual => {}
        (Some(locked), Some(actual)) => {
            violations.push(format!("{} mismatch: Cell.lock has '{}', metadata has '{}'", field, locked, actual))
        }
        (None, _) => {}
        (_, None) => violations.push(format!("metadata has no {}", field)),
    }
}

fn deployment_status_violation(deployment: &crate::package::DeploymentRecord) -> Option<String> {
    match deployment.status.as_ref() {
        Some(crate::package::DeploymentStatus::Active) => None,
        Some(status) => Some(format!("deployment for network '{}' is not active: {:?}", deployment.network, status)),
        None => Some(format!("deployment for network '{}' has no status; expected active", deployment.network)),
    }
}

fn push_deployment_status_violation(deployment: &crate::package::DeploymentRecord, violations: &mut Vec<String>) {
    if let Some(violation) = deployment_status_violation(deployment) {
        violations.push(violation);
    }
}

fn verify_registry_trust_metadata(
    deployed: &crate::package::DeployedManifest,
    require_publisher_signature: bool,
    require_audit_report: bool,
    violations: &mut Vec<String>,
) -> serde_json::Value {
    let mut evidence = Vec::new();
    if (require_publisher_signature || require_audit_report) && deployed.deployments.is_empty() {
        violations.push("trust metadata policy requires at least one deployment record".to_string());
    }
    for deployment in &deployed.deployments {
        let publisher_signature_present = deployment.publisher_signature.as_deref().is_some_and(|value| !value.trim().is_empty());
        let audit_report_hash_present = deployment.audit_report_hash.as_deref().is_some_and(|value| !value.trim().is_empty());
        let mut deployment_violations = Vec::new();
        if require_publisher_signature && !publisher_signature_present {
            deployment_violations.push(format!(
                "deployment for network '{}' has no publisher_signature required by trust metadata policy",
                deployment.network
            ));
        }
        if require_audit_report && !audit_report_hash_present {
            deployment_violations.push(format!(
                "deployment for network '{}' has no audit_report_hash required by trust metadata policy",
                deployment.network
            ));
        }
        for violation in &deployment_violations {
            if !violations.contains(violation) {
                violations.push(violation.clone());
            }
        }
        evidence.push(serde_json::json!({
            "network": deployment.network,
            "out_point": deployment.out_point,
            "status": if deployment_violations.is_empty() { "policy-satisfied" } else { "failed" },
            "publisher_signature_present": publisher_signature_present,
            "publisher_signature_status": if publisher_signature_present {
                "present-unverified"
            } else if require_publisher_signature {
                "missing"
            } else {
                "not-required"
            },
            "audit_report_hash_present": audit_report_hash_present,
            "audit_report_hash_status": if audit_report_hash_present {
                "present"
            } else if require_audit_report {
                "missing"
            } else {
                "not-required"
            },
            "violations": deployment_violations,
        }));
    }
    serde_json::json!({
        "enabled": require_publisher_signature || require_audit_report,
        "checked": deployed.deployments.len(),
        "verification_boundary": "metadata-presence-only",
        "publisher_signature_verification": "not-implemented",
        "policy": {
            "require_publisher_signature": require_publisher_signature,
            "require_audit_report": require_audit_report,
        },
        "evidence": evidence,
    })
}

fn compare_builder_deployed_field(
    field: &str,
    deployed_value: &Option<String>,
    metadata_value: &Option<String>,
    violations: &mut Vec<String>,
) {
    match (deployed_value, metadata_value) {
        (Some(deployed), Some(actual)) if deployed == actual => {}
        (Some(deployed), Some(actual)) => {
            violations.push(format!("{} mismatch: Deployed.toml has '{}', metadata has '{}'", field, deployed, actual))
        }
        (None, _) => {}
        (_, None) => violations.push(format!("metadata has no {}", field)),
    }
}

fn compare_builder_deployment_record_field(
    field: &str,
    deployed_value: &Option<String>,
    metadata_value: &Option<String>,
    network: &str,
    violations: &mut Vec<String>,
) {
    match (deployed_value, metadata_value) {
        (Some(deployed), Some(actual)) if deployed == actual => {}
        (Some(deployed), Some(actual)) => violations.push(format!(
            "{} mismatch for network '{}': Deployed.toml has '{}', metadata has '{}'",
            field, network, deployed, actual
        )),
        (None, _) => violations.push(format!("deployment record for network '{}' has no {}", network, field)),
        (_, None) => violations.push(format!("metadata has no {}", field)),
    }
}

fn compare_required_deployment_ref_field(
    field: &str,
    locked_value: Option<&str>,
    deployed_value: &str,
    network: &str,
    violations: &mut Vec<String>,
) {
    match locked_value {
        Some(locked) if locked == deployed_value => {}
        Some(locked) => violations.push(format!(
            "{} mismatch for network '{}': Cell.lock has '{}', Deployed.toml has '{}'",
            field, network, locked, deployed_value
        )),
        None => violations.push(format!("deployment ref for network '{}' has no {}", network, field)),
    }
}

fn write_typescript_builder_package(
    output_dir: &Path,
    package_name: &str,
    metadata: &CompileMetadata,
    metadata_hash: &str,
    actions: &[&crate::ActionMetadata],
    locked_identity: Option<&serde_json::Value>,
    deployment_identity: Option<&serde_json::Value>,
    lockfile_path: Option<&Path>,
    deployed_path: Option<&Path>,
) -> Result<serde_json::Value> {
    let src_dir = output_dir.join("src");
    let test_dir = output_dir.join("test");
    std::fs::create_dir_all(&src_dir)?;
    std::fs::create_dir_all(&test_dir)?;

    let manifest = typescript_builder_manifest(package_name, metadata, actions, metadata_hash, locked_identity, deployment_identity);

    let package_json_path = output_dir.join("package.json");
    let tsconfig_path = output_dir.join("tsconfig.json");
    let manifest_path = output_dir.join("cellscript-builder-manifest.json");
    let metadata_path = src_dir.join("metadata.json");
    let index_path = src_dir.join("index.ts");
    let test_path = test_dir.join("builder.test.mjs");

    std::fs::write(&package_json_path, json_bytes_pretty("package.json", &typescript_package_json(package_name))?)?;
    std::fs::write(&tsconfig_path, json_bytes_pretty("tsconfig.json", &typescript_tsconfig_json())?)?;
    std::fs::write(&manifest_path, json_bytes_pretty("builder manifest", &manifest)?)?;
    std::fs::write(&metadata_path, json_bytes_pretty("metadata", metadata)?)?;
    std::fs::write(
        &index_path,
        typescript_builder_index(package_name, metadata, actions, metadata_hash, locked_identity, deployment_identity)?,
    )?;
    std::fs::write(&test_path, typescript_builder_test(actions)?)?;
    let policy_test_path = test_dir.join("policy-witness.test.mjs");
    let policy_test_source = include_str!("policy_builder_test.mjs");
    if metadata.runtime.policy_artifact.is_some() {
        std::fs::write(&policy_test_path, policy_test_source)?;
    } else if std::fs::read(&policy_test_path).is_ok_and(|bytes| bytes == policy_test_source.as_bytes()) {
        // Remove only our exact generated policy test when this output is
        // regenerated for the legacy path; preserve any user-edited test.
        std::fs::remove_file(&policy_test_path)?;
    }

    Ok(serde_json::json!({
        "status": "ok",
        "schema": "cellscript-generated-builder-summary-v0.20",
        "target": "typescript",
        "output_dir": output_dir.display().to_string(),
        "package_name": package_name,
        "metadata_hash": metadata_hash,
        "artifact_hash": metadata.artifact_hash,
        "cell_data_codec_abi": metadata.cell_data_codec_manifest.abi,
        "raw_cell_data_required": metadata.cell_data_codec_manifest.raw_bytes_required,
        "lockfile_verified": locked_identity.is_some(),
        "deployment_verified": deployment_identity.is_some(),
        "lockfile": lockfile_path.map(|path| path.display().to_string()),
        "deployed": deployed_path.map(|path| path.display().to_string()),
        "action_count": actions.len(),
        "actions": actions.iter().map(|action| action.name.as_str()).collect::<Vec<_>>(),
        "files": [
            package_json_path.display().to_string(),
            tsconfig_path.display().to_string(),
            manifest_path.display().to_string(),
            metadata_path.display().to_string(),
            index_path.display().to_string(),
            test_path.display().to_string()
        ],
        "non_claims": [
            "generated package does not prove live-cell availability",
            "generated package does not sign or submit transactions by itself",
            "generated package does not materialize raw cell-data codecs by itself",
            "generated package requires a runtime adapter for CCC or ckb-sdk-rust"
        ]
    }))
}

fn runtime_error_catalog_json() -> Vec<serde_json::Value> {
    ALL_RUNTIME_ERRORS
        .iter()
        .copied()
        .map(|error| {
            let info = runtime_error_info(error);
            serde_json::json!({
                "code": info.code,
                "name": info.name,
                "description": info.description,
                "hint": info.hint,
            })
        })
        .collect()
}

fn action_requires_entry_witness(action: &crate::ActionMetadata) -> bool {
    let runtime_bound = crate::runtime_bound_param_names(&action.params);
    action.params.iter().any(|param| crate::param_consumes_entry_witness_payload(param, &runtime_bound))
}

fn builder_action_error_contexts_json(actions: &[&crate::ActionMetadata]) -> Vec<serde_json::Value> {
    actions
        .iter()
        .map(|action| {
            serde_json::json!({
                "action": action.name,
                "fields": action
                    .params
                    .iter()
                    .map(|param| {
                        serde_json::json!({
                            "name": param.name,
                            "type": param.ty,
                            "source": param.source,
                            "is_mut": param.is_mut,
                            "is_ref": param.is_ref,
                            "witness_data_source": param.witness_data_source,
                            "lock_args_data_source": param.lock_args_data_source,
                            "protected_spend_surface": param.protected_spend_surface,
                            "cell_bound_abi": param.cell_bound_abi,
                            "schema_pointer_abi": param.schema_pointer_abi,
                            "schema_length_abi": param.schema_length_abi,
                            "fixed_byte_len": param.fixed_byte_len,
                        })
                    })
                    .collect::<Vec<_>>(),
                "entry_witness_required": action_requires_entry_witness(action),
                "runtimeInputRequirements": action.transaction_runtime_input_requirements,
                "actionScanSelectors": action_scan_selectors_json(action),
                "verifierObligations": action.verifier_obligations,
                "failClosedRuntimeFeatures": action.fail_closed_runtime_features,
            })
        })
        .collect()
}

fn typescript_builder_manifest(
    package_name: &str,
    metadata: &CompileMetadata,
    actions: &[&crate::ActionMetadata],
    metadata_hash: &str,
    locked_identity: Option<&serde_json::Value>,
    deployment_identity: Option<&serde_json::Value>,
) -> serde_json::Value {
    let mut manifest = serde_json::json!({
        "schema": "cellscript-generated-action-builder-v0.23-edition-2026",
        "target": "typescript",
        "package_name": package_name,
        "module": metadata.module,
        "compiler_version": metadata.compiler_version,
        "edition": metadata.edition,
        "compatibility_profile": metadata.compatibility_profile,
        "metadata_schema_version": metadata.metadata_schema_version,
        "metadata_schema_versions": metadata_schema_versions_json(metadata),
        "metadata_hash": metadata_hash,
        "artifact_hash": metadata.artifact_hash,
        "source_hash": metadata.source_hash,
        "target_profile": metadata.target_profile.name,
        "molecule_schema_manifest": metadata.molecule_schema_manifest,
        "cell_data_codec_manifest": metadata.cell_data_codec_manifest,
        "locked_identity": locked_identity,
        "deployment_identity": deployment_identity,
        "actions": actions
            .iter()
            .map(|action| {
                serde_json::json!({
                    "name": action.name,
                    "params": action.params,
                    "created_outputs": action.create_set.len(),
                    "mutated_outputs": action.mutate_set.len(),
                    "runtime_input_requirements": action.transaction_runtime_input_requirements.len(),
                    "runtime_accesses": action.ckb_runtime_accesses,
                    "action_scan_selectors": action_scan_selectors_json(action),
                    "entry_witness_required": action_requires_entry_witness(action),
                })
            })
            .collect::<Vec<_>>(),
        "transaction_view_handles": metadata.runtime.transaction_view_handles,
        "signing_message_domains": metadata.runtime.signing_message_domains,
        "runtime_error_catalog": runtime_error_catalog_json(),
        "runtime_contract": {
            "requires_live_cell_resolution": true,
            "requires_deployment_resolution": true,
            "requires_capacity_and_fee_policy": true,
            "requires_witness_materialization": true,
            "requires_cell_data_codec_materialization": true,
            "requires_external_cell_data_codec_adapter": metadata.cell_data_codec_manifest.raw_bytes_required,
            "cell_data_codec_abi": metadata.cell_data_codec_manifest.abi,
            "requires_dry_run_before_submit": true,
            "must_not_infer_protocol_semantics_from_action_name": true,
            "action_scan_selectors_schema": "cellscript-action-scan-selectors-v0.21",
            "action_scan_selector_source": "transaction_runtime_input_requirements",
            "runtime_access_provenance": metadata.runtime.ckb_runtime_access_provenance_contract,
            "requires_pre_signing_witness_placement": !metadata.runtime.signing_message_domains.is_empty(),
            "temporal_interface": metadata.public_interface.runtime_contract.temporal,
        }
    });
    if let Some(policy) = &metadata.runtime.policy_artifact {
        manifest["policy_artifact"] = serde_json::json!(policy);
        manifest["runtime_contract"]["requires_policy_witness_bundle"] = serde_json::json!(true);
        manifest["runtime_contract"]["requires_full_script_hash"] = serde_json::json!(true);
        manifest["runtime_contract"]["requires_shared_witness_aggregation"] = serde_json::json!(true);
        manifest["runtime_contract"]["requires_pre_signing_placement"] = serde_json::json!(true);
        manifest["runtime_contract"]["policy_args_encoding"] = serde_json::json!("pre-encoded-inner-CSARGv1");
        for action in manifest["actions"].as_array_mut().expect("generated actions array") {
            let name = action["name"].as_str().expect("generated action name");
            action["policy_tag"] = serde_json::json!(policy.declaration.action(name).expect("selected exported action").tag);
            action["policy_witness_required"] = serde_json::json!(true);
        }
    }
    manifest
}

fn typescript_package_json(package_name: &str) -> serde_json::Value {
    serde_json::json!({
        "name": package_name,
        "version": "0.0.0-cellscript-generated",
        "private": true,
        "type": "module",
        "main": "dist/index.js",
        "types": "dist/index.d.ts",
        "scripts": {
            "build": "tsc -p tsconfig.json",
            "test": "npm run build && node --test test/*.test.mjs"
        },
        "devDependencies": {
            "typescript": "^5.0.0"
        }
    })
}

fn typescript_tsconfig_json() -> serde_json::Value {
    serde_json::json!({
        "compilerOptions": {
            "target": "ES2022",
            "module": "NodeNext",
            "moduleResolution": "NodeNext",
            "declaration": true,
            "outDir": "dist",
            "rootDir": "src",
            "strict": true,
            "resolveJsonModule": true,
            "esModuleInterop": true,
            "skipLibCheck": true
        },
        "include": ["src/**/*.ts", "src/**/*.json"]
    })
}

fn typescript_builder_index(
    package_name: &str,
    metadata: &CompileMetadata,
    actions: &[&crate::ActionMetadata],
    metadata_hash: &str,
    locked_identity: Option<&serde_json::Value>,
    deployment_identity: Option<&serde_json::Value>,
) -> Result<String> {
    let action_specs = actions
        .iter()
        .map(|action| {
            serde_json::json!({
                "name": action.name,
                "params": action.params,
                "createSet": action.create_set,
                "mutateSet": action.mutate_set,
                "readRefs": action.read_refs,
                "verifierObligations": action.verifier_obligations,
                "runtimeInputRequirements": action.transaction_runtime_input_requirements,
                "runtimeAccesses": action.ckb_runtime_accesses,
                "actionScanSelectors": action_scan_selectors_json(action),
                "failClosedRuntimeFeatures": action.fail_closed_runtime_features,
            })
        })
        .collect::<Vec<_>>();
    let action_specs_json = json_string_pretty("action specs", &action_specs)?;
    let action_error_contexts_json = json_string_pretty("action error contexts", &builder_action_error_contexts_json(actions))?;
    let runtime_error_catalog_json = json_string_pretty("runtime error catalog", &runtime_error_catalog_json())?;
    let manifest_json = json_string_pretty(
        "builder manifest",
        &typescript_builder_manifest(package_name, metadata, actions, metadata_hash, locked_identity, deployment_identity),
    )?;
    let metadata_json = json_string_pretty("metadata", metadata)?;
    let signing_message_domains_json = json_string_pretty("signing message domains", &metadata.runtime.signing_message_domains)?;

    let mut ts = String::new();
    ts.push_str("export const CELLSCRIPT_BUILDER_SCHEMA = \"cellscript-generated-action-builder-v0.23-edition-2026\" as const;\n");
    ts.push_str("export const ACTION_SCAN_SELECTORS_SCHEMA = \"cellscript-action-scan-selectors-v0.21\" as const;\n");
    ts.push_str(&format!("export const builderManifest = {manifest_json} as const;\n"));
    ts.push_str(&format!("export const metadata = {metadata_json} as const;\n"));
    ts.push_str("export const cellDataCodecManifest = metadata.cell_data_codec_manifest;\n");
    ts.push_str("export const temporalContract = metadata.public_interface.runtime_contract.temporal;\n");
    ts.push_str("export const runtimeAccessProvenanceContract = metadata.runtime.ckb_runtime_access_provenance_contract;\n");
    ts.push_str("export const transactionViewHandles = metadata.runtime.transaction_view_handles;\n");
    ts.push_str(&format!("export const signingMessageDomains = {signing_message_domains_json} as const;\n"));
    ts.push_str(&format!("export const actionSpecs = {action_specs_json} as const;\n\n"));
    ts.push_str(&format!("export const actionErrorContexts = {action_error_contexts_json} as const;\n"));
    ts.push_str(&format!("export const runtimeErrorCatalog = {runtime_error_catalog_json} as const;\n\n"));
    ts.push_str(
        "export type HexString = `0x${string}`;\n\
         export type CellScriptScalarInput = bigint | number | string;\n\
         export type CellScriptTemporalDomain = \"EpochNumber\" | \"EpochDuration\" | \"BlockNumber\" | \"EpochLength\" | \"TimestampMillis\" | \"EncodedSince\" | \"DecodedSince\" | \"AbsoluteBlockSince\" | \"AbsoluteEpochSince\" | \"AbsoluteTimestampSince\" | \"RelativeBlockSince\" | \"RelativeEpochSince\" | \"RelativeTimestampSince\";\n\
         declare const cellScriptTemporalDomain: unique symbol;\n\
         export type CellScriptTemporalInput<D extends CellScriptTemporalDomain> = CellScriptScalarInput & { readonly [cellScriptTemporalDomain]: D };\n\
         export type EpochNumber = CellScriptTemporalInput<\"EpochNumber\">;\n\
         export type EpochDuration = CellScriptTemporalInput<\"EpochDuration\">;\n\
         export type BlockNumber = CellScriptTemporalInput<\"BlockNumber\">;\n\
         export type EpochLength = CellScriptTemporalInput<\"EpochLength\">;\n\
         export type TimestampMillis = CellScriptTemporalInput<\"TimestampMillis\">;\n\
         export type EncodedSince = CellScriptTemporalInput<\"EncodedSince\">;\n\
         export type DecodedSince = CellScriptTemporalInput<\"DecodedSince\">;\n\
         export type AbsoluteBlockSince = CellScriptTemporalInput<\"AbsoluteBlockSince\">;\n\
         export type AbsoluteEpochSince = CellScriptTemporalInput<\"AbsoluteEpochSince\">;\n\
         export type AbsoluteTimestampSince = CellScriptTemporalInput<\"AbsoluteTimestampSince\">;\n\
         export type RelativeBlockSince = CellScriptTemporalInput<\"RelativeBlockSince\">;\n\
         export type RelativeEpochSince = CellScriptTemporalInput<\"RelativeEpochSince\">;\n\
         export type RelativeTimestampSince = CellScriptTemporalInput<\"RelativeTimestampSince\">;\n\n\
         export function temporalValue<D extends CellScriptTemporalDomain>(domain: D, value: CellScriptScalarInput): CellScriptTemporalInput<D> {\n\
           void domain;\n\
           return value as CellScriptTemporalInput<D>;\n\
         }\n\n\
         export type CellScriptValue = string | number | bigint | boolean | Uint8Array | Record<string, unknown> | null;\n\
         export type CellScriptParams = object;\n\n\
         export type ActionScanSelectors = Record<string, unknown> & {\n\
           schema: typeof ACTION_SCAN_SELECTORS_SCHEMA;\n\
           source?: string;\n\
           status?: string;\n\
           selector_count?: number;\n\
           selectors?: readonly unknown[];\n\
         };\n\n\
         export type ScanSelectorEvidence = Record<string, unknown> & {\n\
           selector_index: number;\n\
           status: \"resolved\";\n\
           source?: string;\n\
           role?: string;\n\
           binding?: string;\n\
           feature?: string;\n\
           component?: string;\n\
           script_field?: string | null;\n\
         };\n\n\
         export interface CellScriptLockfilePackage {\n\
           edition: \"2026\";\n\
           name?: string;\n\
           version?: string;\n\
           namespace?: string | null;\n\
           source_hash?: string | null;\n\
           compiler_source_hash?: string | null;\n\
         }\n\n\
         export interface CellScriptLockfileBuild {\n\
           edition: \"2026\";\n\
           compatibility_profile_hash: string;\n\
           compiler_version?: string | null;\n\
           target_profile?: string | null;\n\
           artifact_hash?: string | null;\n\
           metadata_hash?: string | null;\n\
           schema_hash?: string | null;\n\
           cell_data_codec_manifest_hash?: string | null;\n\
           abi_hash?: string | null;\n\
           constraints_hash?: string | null;\n\
         }\n\n\
         export interface CellScriptLockfileDeployment {\n\
           record?: string | null;\n\
           record_hash?: string | null;\n\
           code_hash?: string | null;\n\
           out_point?: string | null;\n\
           data_hash?: string | null;\n\
         }\n\n\
         export interface CellScriptLockfile {\n\
           package?: CellScriptLockfilePackage;\n\
           package_build?: CellScriptLockfileBuild | null;\n\
           deployment?: Record<string, CellScriptLockfileDeployment | null | undefined>;\n\
         }\n\n\
         export interface CellScriptDeploymentRecord {\n\
           edition: \"2026\";\n\
           network: string;\n\
           chain_id: string;\n\
           tx_hash: string;\n\
           output_index: number;\n\
           code_hash: string;\n\
           hash_type: string;\n\
           dep_type: string;\n\
           data_hash: string;\n\
           out_point: string;\n\
           artifact_hash?: string | null;\n\
           metadata_hash?: string | null;\n\
           schema_hash?: string | null;\n\
           cell_data_codec_manifest_hash?: string | null;\n\
           abi_hash?: string | null;\n\
           constraints_hash?: string | null;\n\
           compiler_version?: string | null;\n\
           compatibility_profile_hash: string;\n\
           type_id?: string | null;\n\
           status?: string | null;\n\
           audit_report_hash?: string | null;\n\
           publisher_signature?: string | null;\n\
         }\n\n\
         export interface CellScriptLiveDeploymentEvidence {\n\
           network?: string;\n\
           out_point?: string;\n\
           rpc_status?: string;\n\
           status?: string;\n\
           deployment_status?: string | null;\n\
           expected_data_hash?: string;\n\
           rpc_data_hash?: string | null;\n\
           expected_code_hash?: string;\n\
           rpc_code_hash?: string | null;\n\
           violations?: readonly string[];\n\
         }\n\n\
         export interface CellScriptTrustPolicy {\n\
           requirePublisherSignature?: boolean;\n\
           requireAuditReportHash?: boolean;\n\
         }\n\n\
         export interface BuildOptions {\n\
           lockfile?: CellScriptLockfile;\n\
           deployment?: CellScriptDeploymentRecord;\n\
           liveDeploymentEvidence?: CellScriptLiveDeploymentEvidence;\n\
           trustPolicy?: CellScriptTrustPolicy;\n\
           deploymentRef?: string;\n\
           dryRun?: boolean;\n\
           submit?: boolean;\n\
           feeRate?: bigint | number | string;\n\
           changeLock?: unknown;\n\
         }\n\n\
         export interface ActionBuilderPlan<P extends CellScriptParams = CellScriptParams> {\n\
           schema: typeof CELLSCRIPT_BUILDER_SCHEMA;\n\
           state: \"GeneratedActionPlan\";\n\
           status: \"requires-runtime-resolution\";\n\
           action: string;\n\
           params: P;\n\
           options: BuildOptions;\n\
           metadataHash: string;\n\
           artifactHash: string | null;\n\
           targetProfile: string;\n\
           canSubmit: false;\n\
         requiresLiveCellResolution: true;\n\
         requiresDeploymentResolution: true;\n\
         cellDataCodecManifest: typeof cellDataCodecManifest;\n\
         temporalContract: typeof temporalContract;\n\
         runtimeAccessProvenanceContract: typeof runtimeAccessProvenanceContract;\n\
         signingMessageDomains: typeof signingMessageDomains;\n\
         runtimeAccesses: readonly unknown[];\n\
         runtimeInputRequirements: readonly unknown[];\n\
         actionScanSelectors: ActionScanSelectors;\n\
         verifierObligations: readonly unknown[];\n\
         failClosedRuntimeFeatures: readonly string[];\n\
         notProvenByGeneratedBuilder: readonly string[];\n\
       }\n\n\
         export type ActionBuilderMode = \"build\" | \"dry-run\" | \"submit\";\n\n\
         export interface ActionBuilderResult<P extends CellScriptParams = CellScriptParams> {\n\
           schema: typeof CELLSCRIPT_BUILDER_SCHEMA;\n\
           state: \"ActionBuilderResult\";\n\
           status: \"built-by-runtime\" | \"dry-run-by-runtime\" | \"submitted-by-runtime\";\n\
           mode: ActionBuilderMode;\n\
           plan: ActionBuilderPlan<P>;\n\
           liveCellResolution: LiveCellResolutionResult;\n\
           transaction: unknown;\n\
           dryRunResult?: unknown;\n\
           submitResult?: unknown;\n\
           submittedTxHash?: string | null;\n\
           canSubmit: false;\n\
           notProvenByGeneratedBuilder: readonly string[];\n\
         }\n\n\
         export interface LiveCellResolutionRequest<P extends CellScriptParams = CellScriptParams> {\n\
           plan: ActionBuilderPlan<P>;\n\
           options: BuildOptions;\n\
         }\n\n\
         export interface LiveCellResolutionResult {\n\
           inputs?: readonly unknown[];\n\
           referenceInputs?: readonly unknown[];\n\
           cellDeps?: readonly unknown[];\n\
           headerDeps?: readonly unknown[];\n\
           deploymentRef?: unknown;\n\
           lineage?: readonly unknown[];\n\
           scanSelectorEvidence?: readonly ScanSelectorEvidence[];\n\
         }\n\n\
         export interface CellScriptBuilderRuntime {\n\
           resolveLiveCells<P extends CellScriptParams>(request: LiveCellResolutionRequest<P>): Promise<LiveCellResolutionResult>;\n\
           buildTransaction<P extends CellScriptParams>(plan: ActionBuilderPlan<P> & { liveCellResolution: LiveCellResolutionResult }): Promise<unknown>;\n\
           dryRun?(transaction: unknown): Promise<unknown>;\n\
           submit?(transaction: unknown): Promise<unknown>;\n\
         }\n\n\
         export interface CellScriptRuntimeErrorInfo {\n\
           code: number;\n\
           name: string;\n\
           description: string;\n\
           hint: string;\n\
         }\n\n\
         export interface CellScriptActionFieldContext {\n\
           name: string;\n\
           type: string;\n\
           source: string;\n\
           is_mut: boolean;\n\
           is_ref: boolean;\n\
           witness_data_source: boolean;\n\
           lock_args_data_source: boolean;\n\
           protected_spend_surface: boolean;\n\
           cell_bound_abi: boolean;\n\
           schema_pointer_abi: boolean;\n\
           schema_length_abi: boolean;\n\
           fixed_byte_len?: number | null;\n\
         }\n\n\
         export interface CellScriptActionErrorContext {\n\
           action: string;\n\
           fields: readonly CellScriptActionFieldContext[];\n\
         entry_witness_required: boolean;\n\
         runtimeInputRequirements: readonly unknown[];\n\
         actionScanSelectors: ActionScanSelectors;\n\
         verifierObligations: readonly unknown[];\n\
         failClosedRuntimeFeatures: readonly string[];\n\
       }\n\n\
         export interface CellScriptRuntimeErrorExplanation extends CellScriptRuntimeErrorInfo {\n\
           action?: string;\n\
           actionFields: readonly CellScriptActionFieldContext[];\n\
         entryWitnessRequired: boolean;\n\
         runtimeInputRequirements: readonly unknown[];\n\
         actionScanSelectors?: ActionScanSelectors;\n\
         verifierObligations: readonly unknown[];\n\
         failClosedRuntimeFeatures: readonly string[];\n\
       }\n\n",
    );
    ts.push_str(&format!(
        "const GENERATED_METADATA_HASH = {};\n\
         const GENERATED_ARTIFACT_HASH: string | null = {};\n\
         const GENERATED_SOURCE_HASH: string | null = {};\n\
         const GENERATED_COMPILER_VERSION = {};\n\
         const GENERATED_EDITION = {};\n\
         const GENERATED_COMPATIBILITY_PROFILE_HASH = {};\n\
         const GENERATED_TARGET_PROFILE = {};\n\
         const GENERATED_SCHEMA_HASH = {};\n\
         const GENERATED_CELL_DATA_CODEC_MANIFEST_HASH = {};\n\
         const GENERATED_ABI_HASH = {};\n\
         const GENERATED_CONSTRAINTS_HASH = {};\n\
         const BUILDER_MANIFEST_RUNTIME = builderManifest as unknown as {{\n\
           deployment_identity?: {{ deployments?: readonly CellScriptDeploymentRecord[] }} | null;\n\
         }};\n\n",
        typescript_string_literal(metadata_hash),
        metadata.artifact_hash.as_deref().map(typescript_string_literal).unwrap_or_else(|| "null".to_string()),
        metadata.source_hash.as_deref().map(typescript_string_literal).unwrap_or_else(|| "null".to_string()),
        typescript_string_literal(&metadata.compiler_version),
        typescript_string_literal(metadata.edition.as_str()),
        typescript_string_literal(&hash_json_value("compatibility_profile", &metadata.compatibility_profile,)?),
        typescript_string_literal(&metadata.target_profile.name),
        typescript_string_literal(&metadata.molecule_schema_manifest.manifest_hash),
        typescript_string_literal(&metadata.cell_data_codec_manifest.manifest_hash),
        typescript_string_literal(&metadata_abi_hash(metadata)?),
        typescript_string_literal(&hash_json_value("constraints", &metadata.constraints)?),
    ));
    ts.push_str(
        "export function runtimeErrorInfoByCode(code: number | string | bigint): CellScriptRuntimeErrorInfo | null {\n\
           const parsed = runtimeErrorCodeFrom(code);\n\
           if (parsed === null) {\n\
             return null;\n\
           }\n\
           const item = runtimeErrorCatalog.find((error) => error.code === parsed);\n\
           return item ? { code: item.code, name: item.name, description: item.description, hint: item.hint } : null;\n\
         }\n\n\
         export function runtimeErrorInfoByName(name: string): CellScriptRuntimeErrorInfo | null {\n\
           const normalized = name.trim().toLowerCase();\n\
           const item = runtimeErrorCatalog.find((error) => error.name === normalized);\n\
           return item ? { code: item.code, name: item.name, description: item.description, hint: item.hint } : null;\n\
         }\n\n\
         export function runtimeErrorContextForAction(action: string): CellScriptActionErrorContext | null {\n\
           const context = actionErrorContexts.find((item) => item.action === action);\n\
           if (!context) {\n\
             return null;\n\
           }\n\
           return {\n\
             action: context.action,\n\
             fields: context.fields.map((field) => ({ ...field })),\n\
             entry_witness_required: context.entry_witness_required,\n\
             runtimeInputRequirements: [...context.runtimeInputRequirements],\n\
             actionScanSelectors: context.actionScanSelectors as ActionScanSelectors,\n\
             verifierObligations: [...context.verifierObligations],\n\
             failClosedRuntimeFeatures: [...context.failClosedRuntimeFeatures],\n\
           };\n\
         }\n\n\
         export function explainCellScriptRuntimeError(error: unknown, action?: string): CellScriptRuntimeErrorExplanation | null {\n\
           const code = runtimeErrorCodeFrom(error);\n\
           const name = runtimeErrorNameFrom(error);\n\
           const message = runtimeErrorMessageFrom(error);\n\
           let info = code === null ? null : runtimeErrorInfoByCode(code);\n\
           if (!info && name) {\n\
             info = runtimeErrorInfoByName(name);\n\
           }\n\
           if (!info && message) {\n\
             const normalizedMessage = message.toLowerCase();\n\
             const item = runtimeErrorCatalog.find((known) => normalizedMessage.includes(known.name));\n\
             info = item ? { code: item.code, name: item.name, description: item.description, hint: item.hint } : null;\n\
             if (!info && (normalizedMessage.includes(\"entry witness\") || normalizedMessage.includes(\"entry-witness\"))) {\n\
               info = runtimeErrorInfoByName(\"entry-witness-abi-invalid\");\n\
             }\n\
             if (!info && normalizedMessage.includes(\"collection\")) {\n\
               info = runtimeErrorInfoByName(\"collection-runtime-unsupported\");\n\
             }\n\
           }\n\
           if (!info) {\n\
             return null;\n\
           }\n\
           const context = action ? runtimeErrorContextForAction(action) : null;\n\
           return {\n\
             ...info,\n\
             action: context?.action ?? action,\n\
             actionFields: context?.fields ?? [],\n\
             entryWitnessRequired: context?.entry_witness_required ?? false,\n\
             runtimeInputRequirements: context?.runtimeInputRequirements ?? [],\n\
             actionScanSelectors: context?.actionScanSelectors,\n\
             verifierObligations: context?.verifierObligations ?? [],\n\
             failClosedRuntimeFeatures: context?.failClosedRuntimeFeatures ?? [],\n\
           };\n\
         }\n\n\
         function runtimeErrorCodeFrom(error: unknown): number | null {\n\
           if (typeof error === \"number\" && Number.isFinite(error)) {\n\
             return Math.trunc(error);\n\
           }\n\
           if (typeof error === \"bigint\") {\n\
             const value = Number(error);\n\
             return Number.isSafeInteger(value) ? value : null;\n\
           }\n\
           if (typeof error === \"string\") {\n\
             const trimmed = error.trim();\n\
             return /^-?\\d+$/.test(trimmed) ? Number(trimmed) : null;\n\
           }\n\
           if (typeof error === \"object\" && error !== null) {\n\
             const record = error as Record<string, unknown>;\n\
             for (const key of [\"code\", \"exitCode\", \"errorCode\", \"error_code\", \"ecode\"] as const) {\n\
               const parsed = runtimeErrorCodeFrom(record[key]);\n\
               if (parsed !== null) {\n\
                 return parsed;\n\
               }\n\
             }\n\
           }\n\
           return null;\n\
         }\n\n\
         function runtimeErrorNameFrom(error: unknown): string | null {\n\
           if (typeof error === \"string\") {\n\
             const trimmed = error.trim().toLowerCase();\n\
             return runtimeErrorCatalog.some((known) => known.name === trimmed) ? trimmed : null;\n\
           }\n\
           if (typeof error === \"object\" && error !== null) {\n\
             const record = error as Record<string, unknown>;\n\
             for (const key of [\"name\", \"error\", \"errorName\", \"runtime_error\"] as const) {\n\
               const value = record[key];\n\
               if (typeof value === \"string\") {\n\
                 const match = runtimeErrorNameFrom(value);\n\
                 if (match) {\n\
                   return match;\n\
                 }\n\
               }\n\
             }\n\
           }\n\
           return null;\n\
         }\n\n\
         function runtimeErrorMessageFrom(error: unknown): string | null {\n\
           if (typeof error === \"string\") {\n\
             return error;\n\
           }\n\
           if (typeof error === \"object\" && error !== null) {\n\
             const record = error as Record<string, unknown>;\n\
             for (const key of [\"message\", \"stderr\", \"reason\"] as const) {\n\
               const value = record[key];\n\
               if (typeof value === \"string\") {\n\
                 return value;\n\
               }\n\
             }\n\
           }\n\
           return null;\n\
         }\n\n\
         export function validateCellScriptLockfile(lockfile: CellScriptLockfile): string[] {\n\
           const violations: string[] = [];\n\
           const pkg = lockfile.package;\n\
           if (!pkg) {\n\
             violations.push(\"Cell.lock has no [package]\");\n\
           } else {\n\
             compareRequiredIdentity(\"edition\", pkg.edition, GENERATED_EDITION, violations);\n\
             compareRequiredIdentity(\"compiler_source_hash\", pkg.compiler_source_hash ?? pkg.source_hash, GENERATED_SOURCE_HASH, violations);\n\
           }\n\
           const build = lockfile.package_build;\n\
           if (!build) {\n\
             violations.push(\"Cell.lock has no [package.build]\");\n\
           } else {\n\
             compareRequiredIdentity(\"edition\", build.edition, GENERATED_EDITION, violations);\n\
             compareRequiredIdentity(\"compatibility_profile_hash\", build.compatibility_profile_hash, GENERATED_COMPATIBILITY_PROFILE_HASH, violations);\n\
             compareRequiredIdentity(\"compiler_version\", build.compiler_version, GENERATED_COMPILER_VERSION, violations);\n\
             compareRequiredIdentity(\"target_profile\", build.target_profile, GENERATED_TARGET_PROFILE, violations);\n\
             compareRequiredIdentity(\"artifact_hash\", build.artifact_hash, GENERATED_ARTIFACT_HASH, violations);\n\
             compareRequiredIdentity(\"metadata_hash\", build.metadata_hash, GENERATED_METADATA_HASH, violations);\n\
             compareRequiredIdentity(\"schema_hash\", build.schema_hash, GENERATED_SCHEMA_HASH, violations);\n\
             compareRequiredIdentity(\"cell_data_codec_manifest_hash\", build.cell_data_codec_manifest_hash, GENERATED_CELL_DATA_CODEC_MANIFEST_HASH, violations);\n\
             compareRequiredIdentity(\"abi_hash\", build.abi_hash, GENERATED_ABI_HASH, violations);\n\
             compareRequiredIdentity(\"constraints_hash\", build.constraints_hash, GENERATED_CONSTRAINTS_HASH, violations);\n\
           }\n\
           return violations;\n\
         }\n\n\
         export function assertCellScriptLockfile(lockfile: CellScriptLockfile): void {\n\
           const violations = validateCellScriptLockfile(lockfile);\n\
           if (violations.length > 0) {\n\
             throw new Error(\"CellScript builder identity mismatch: \" + violations.join(\"; \"));\n\
           }\n\
         }\n\n\
         export function validateCellScriptDeployment(\n\
           lockfile?: CellScriptLockfile,\n\
           deployment?: CellScriptDeploymentRecord,\n\
           liveEvidence?: CellScriptLiveDeploymentEvidence,\n\
           trustPolicy?: CellScriptTrustPolicy,\n\
         ): string[] {\n\
           const violations: string[] = [];\n\
           if (!deployment) {\n\
             if (liveEvidence) {\n\
               violations.push(\"live deployment evidence requires a deployment record\");\n\
             }\n\
             violations.push(...validateCellScriptDeploymentTrust(deployment, trustPolicy));\n\
             return violations;\n\
           }\n\
           violations.push(...validateCellScriptDeploymentTrust(deployment, trustPolicy));\n\
           compareDeploymentIdentity(\"edition\", deployment.edition, GENERATED_EDITION, violations);\n\
           compareDeploymentIdentity(\"compatibility_profile_hash\", deployment.compatibility_profile_hash, GENERATED_COMPATIBILITY_PROFILE_HASH, violations);\n\
           if (!deployment.status) {\n\
             violations.push(\"deployment record has no status; expected 'active'\");\n\
           } else if (deployment.status !== \"active\") {\n\
             violations.push(\"deployment status is '\" + deployment.status + \"'\");\n\
           }\n\
           compareDeploymentIdentity(\"compiler_version\", deployment.compiler_version, GENERATED_COMPILER_VERSION, violations);\n\
           compareDeploymentIdentity(\"artifact_hash\", deployment.artifact_hash, GENERATED_ARTIFACT_HASH, violations);\n\
           compareDeploymentIdentity(\"metadata_hash\", deployment.metadata_hash, GENERATED_METADATA_HASH, violations);\n\
           compareDeploymentIdentity(\"schema_hash\", deployment.schema_hash, GENERATED_SCHEMA_HASH, violations);\n\
           compareDeploymentIdentity(\"cell_data_codec_manifest_hash\", deployment.cell_data_codec_manifest_hash, GENERATED_CELL_DATA_CODEC_MANIFEST_HASH, violations);\n\
           compareDeploymentIdentity(\"abi_hash\", deployment.abi_hash, GENERATED_ABI_HASH, violations);\n\
           compareDeploymentIdentity(\"constraints_hash\", deployment.constraints_hash, GENERATED_CONSTRAINTS_HASH, violations);\n\
\n\
           const lockDeployment = lockfile?.deployment?.[deployment.network];\n\
           if (lockfile && !lockDeployment) {\n\
             violations.push(\"Cell.lock has no deployment ref for network '\" + deployment.network + \"'\");\n\
           } else if (lockDeployment) {\n\
             compareHexIdentity(\"deployment.code_hash\", lockDeployment.code_hash, deployment.code_hash, violations);\n\
             compareStringIdentity(\"deployment.out_point\", lockDeployment.out_point, deployment.out_point, violations);\n\
             compareHexIdentity(\"deployment.data_hash\", lockDeployment.data_hash, deployment.data_hash, violations);\n\
           }\n\
\n\
           const embeddedDeployments = BUILDER_MANIFEST_RUNTIME.deployment_identity?.deployments ?? [];\n\
           if (embeddedDeployments.length > 0) {\n\
             const embedded = embeddedDeployments.find((item) => item.network === deployment.network);\n\
             if (!embedded) {\n\
               violations.push(\"builder manifest has no embedded deployment for network '\" + deployment.network + \"'\");\n\
             } else {\n\
               compareHexIdentity(\"embedded_deployment.code_hash\", deployment.code_hash, embedded.code_hash, violations);\n\
               compareStringIdentity(\"embedded_deployment.out_point\", deployment.out_point, embedded.out_point, violations);\n\
               compareHexIdentity(\"embedded_deployment.data_hash\", deployment.data_hash, embedded.data_hash, violations);\n\
               compareStringIdentity(\"embedded_deployment.hash_type\", deployment.hash_type, embedded.hash_type, violations);\n\
               if (embedded.status || deployment.status) {\n\
                 compareStringIdentity(\"embedded_deployment.status\", deployment.status, embedded.status, violations);\n\
               }\n\
               if (embedded.type_id || deployment.type_id) {\n\
                 compareHexIdentity(\"embedded_deployment.type_id\", deployment.type_id, embedded.type_id, violations);\n\
               }\n\
             }\n\
           }\n\
\n\
           if (liveEvidence) {\n\
             if (liveEvidence.status && liveEvidence.status !== \"live-verified\") {\n\
               violations.push(\"live deployment evidence status is '\" + liveEvidence.status + \"'\");\n\
             }\n\
             if (liveEvidence.rpc_status && liveEvidence.rpc_status !== \"live\") {\n\
               violations.push(\"live deployment RPC status is '\" + liveEvidence.rpc_status + \"'\");\n\
             }\n\
             if (!liveEvidence.deployment_status) {\n\
               violations.push(\"live deployment evidence has no deployment_status\");\n\
             } else if (liveEvidence.deployment_status !== \"active\") {\n\
               violations.push(\"live deployment evidence deployment_status is '\" + liveEvidence.deployment_status + \"'\");\n\
             }\n\
             if (liveEvidence.violations && liveEvidence.violations.length > 0) {\n\
               violations.push(\"live deployment evidence reports violations: \" + liveEvidence.violations.join(\"; \"));\n\
             }\n\
             compareStringIdentity(\"live_deployment.out_point\", liveEvidence.out_point, deployment.out_point, violations);\n\
             compareHexIdentity(\"live_deployment.data_hash\", liveEvidence.rpc_data_hash, deployment.data_hash, violations);\n\
             compareHexIdentity(\"live_deployment.code_hash\", liveEvidence.rpc_code_hash, deployment.code_hash, violations);\n\
           }\n\
           return violations;\n\
         }\n\n\
         export function validateCellScriptDeploymentTrust(\n\
           deployment?: CellScriptDeploymentRecord,\n\
           trustPolicy?: CellScriptTrustPolicy,\n\
         ): string[] {\n\
           const violations: string[] = [];\n\
           const requirePublisherSignature = trustPolicy?.requirePublisherSignature ?? false;\n\
           const requireAuditReportHash = trustPolicy?.requireAuditReportHash ?? false;\n\
           if (!requirePublisherSignature && !requireAuditReportHash) {\n\
             return violations;\n\
           }\n\
           if (!deployment) {\n\
             violations.push(\"trust policy requires a deployment record\");\n\
             return violations;\n\
           }\n\
           if (requirePublisherSignature && !deployment.publisher_signature) {\n\
             violations.push(\"deployment record has no publisher_signature required by trust policy\");\n\
           }\n\
           if (requireAuditReportHash && !deployment.audit_report_hash) {\n\
             violations.push(\"deployment record has no audit_report_hash required by trust policy\");\n\
           }\n\
           return violations;\n\
         }\n\n\
         export function assertCellScriptDeployment(\n\
           lockfile?: CellScriptLockfile,\n\
           deployment?: CellScriptDeploymentRecord,\n\
           liveEvidence?: CellScriptLiveDeploymentEvidence,\n\
           trustPolicy?: CellScriptTrustPolicy,\n\
         ): void {\n\
           const violations = validateCellScriptDeployment(lockfile, deployment, liveEvidence, trustPolicy);\n\
           if (violations.length > 0) {\n\
             throw new Error(\"CellScript deployment identity mismatch: \" + violations.join(\"; \"));\n\
           }\n\
         }\n\n\
         function compareRequiredIdentity(\n\
           field: string,\n\
           actual: string | null | undefined,\n\
           expected: string | null,\n\
           violations: string[],\n\
         ): void {\n\
           if (expected === null || expected === \"\") {\n\
             violations.push(\"generated metadata has no \" + field);\n\
             return;\n\
           }\n\
           if (actual === undefined || actual === null || actual === \"\") {\n\
             violations.push(\"Cell.lock has no \" + field);\n\
             return;\n\
           }\n\
           if (actual !== expected) {\n\
             violations.push(field + \" mismatch: Cell.lock has '\" + actual + \"', metadata has '\" + expected + \"'\");\n\
           }\n\
         }\n\n\
         function compareDeploymentIdentity(\n\
           field: string,\n\
           actual: string | null | undefined,\n\
           expected: string | null,\n\
           violations: string[],\n\
         ): void {\n\
           if (expected === null || expected === \"\") {\n\
             violations.push(\"generated metadata has no \" + field);\n\
             return;\n\
           }\n\
           if (actual === undefined || actual === null || actual === \"\") {\n\
             violations.push(\"deployment record has no \" + field);\n\
             return;\n\
           }\n\
           if (!identityEquals(actual, expected)) {\n\
             violations.push(field + \" mismatch: deployment has '\" + actual + \"', metadata has '\" + expected + \"'\");\n\
           }\n\
         }\n\n\
         function compareStringIdentity(\n\
           field: string,\n\
           actual: string | null | undefined,\n\
           expected: string | null | undefined,\n\
           violations: string[],\n\
         ): void {\n\
           if (expected === undefined || expected === null || expected === \"\") {\n\
             violations.push(\"expected \" + field + \" is missing\");\n\
             return;\n\
           }\n\
           if (actual === undefined || actual === null || actual === \"\") {\n\
             violations.push(field + \" is missing\");\n\
             return;\n\
           }\n\
           if (actual !== expected) {\n\
             violations.push(field + \" mismatch: actual '\" + actual + \"', expected '\" + expected + \"'\");\n\
           }\n\
         }\n\n\
         function compareHexIdentity(\n\
           field: string,\n\
           actual: string | null | undefined,\n\
           expected: string | null | undefined,\n\
           violations: string[],\n\
         ): void {\n\
           if (expected === undefined || expected === null || expected === \"\") {\n\
             violations.push(\"expected \" + field + \" is missing\");\n\
             return;\n\
           }\n\
           if (actual === undefined || actual === null || actual === \"\") {\n\
             violations.push(field + \" is missing\");\n\
             return;\n\
           }\n\
           if (!hexEquals(actual, expected)) {\n\
             violations.push(field + \" mismatch: actual '\" + actual + \"', expected '\" + expected + \"'\");\n\
           }\n\
         }\n\n\
         function identityEquals(actual: string, expected: string): boolean {\n\
           return actual === expected || hexEquals(actual, expected);\n\
         }\n\n\
         function hexEquals(actual: string, expected: string): boolean {\n\
           return actual.replace(/^0x/i, \"\").toLowerCase() === expected.replace(/^0x/i, \"\").toLowerCase();\n\
         }\n\n",
    );

    for action in actions {
        let suffix = typescript_type_suffix(&action.name);
        let params_type = typescript_action_params_type(action);
        ts.push_str(&format!("export interface {suffix}Params {{\n"));
        for param in &action.params {
            ts.push_str(&format!("  {}: {};\n", typescript_object_key(&param.name), typescript_param_type(param)));
        }
        if action.params.is_empty() {
            ts.push_str("  readonly __noParams?: never;\n");
        }
        ts.push_str("}\n\n");
        ts.push_str(&format!(
            "export function plan{suffix}(params: {params_type}, options: BuildOptions = {{}}): ActionBuilderPlan<{params_type}> {{\n  \
             return makeActionPlan({}, params, options);\n}}\n\n",
            typescript_string_literal(&action.name)
        ));
    }

    ts.push_str(
        "function assertRuntimeAccessParams(accesses: readonly unknown[], params: CellScriptParams): void {\n  \
         const values = params as Record<string, unknown>;\n  \
         for (const candidate of accesses) {\n    \
           if (typeof candidate !== \"object\" || candidate === null || Array.isArray(candidate)) {\n      continue;\n    }\n    \
           const access = candidate as Record<string, unknown>;\n    \
           const provenanceValue = access.provenance;\n    \
           if (typeof provenanceValue !== \"object\" || provenanceValue === null || Array.isArray(provenanceValue)) {\n      continue;\n    }\n    \
           const provenance = provenanceValue as Record<string, unknown>;\n    \
           const indexValue = provenance.index;\n    \
           if (typeof indexValue !== \"object\" || indexValue === null || Array.isArray(indexValue)) {\n      continue;\n    }\n    \
           const index = indexValue as Record<string, unknown>;\n    \
           if (index.kind !== \"dynamic\" || typeof index.binding !== \"string\" || !(index.binding in values)) {\n      continue;\n    }\n    \
           const value = runtimeUnsignedBigInt(values[index.binding], index.binding);\n    \
           const maximum = runtimeUnsignedBigInt(index.max_inclusive, index.binding + \" max_inclusive\");\n    \
           if (value > maximum) {\n      \
             throw new Error(\"CellScript runtime access index '\" + index.binding + \"' exceeds max_inclusive \" + maximum.toString());\n    \
           }\n  \
         }\n\
       }\n\n\
         function runtimeUnsignedBigInt(value: unknown, label: string): bigint {\n  \
           if (typeof value === \"bigint\") {\n    \
             if (value < 0n) {\n      throw new Error(\"CellScript runtime access index '\" + label + \"' must be unsigned\");\n    }\n    \
             return value;\n  \
           }\n  \
           if (typeof value === \"number\") {\n    \
             if (!Number.isSafeInteger(value) || value < 0) {\n      \
               throw new Error(\"CellScript runtime access index '\" + label + \"' must be a non-negative safe integer\");\n    \
             }\n    \
             return BigInt(value);\n  \
           }\n  \
           if (typeof value === \"string\" && /^(0|[1-9]\\d*)$/.test(value)) {\n    return BigInt(value);\n  }\n  \
           throw new Error(\"CellScript runtime access index '\" + label + \"' must be bigint, integer number, or unsigned decimal string\");\n\
         }\n\n\
         function makeActionPlan<P extends CellScriptParams>(action: string, params: P, options: BuildOptions): ActionBuilderPlan<P> {\n  \
         const actionSpec = actionSpecs.find((item) => item.name === action);\n  \
         if (!actionSpec) {\n    throw new Error(\"CellScript generated builder has no action spec for '\" + action + \"'\");\n  }\n",
    );
    ts.push_str("  if (options.lockfile) {\n    assertCellScriptLockfile(options.lockfile);\n  }\n");
    ts.push_str(
        "  if (options.deployment || options.liveDeploymentEvidence || options.trustPolicy) {\n    \
         assertCellScriptDeployment(options.lockfile, options.deployment, options.liveDeploymentEvidence, options.trustPolicy);\n  }\n",
    );
    ts.push_str("  assertRuntimeAccessParams(actionSpec.runtimeAccesses, params);\n");
    ts.push_str(&format!(
        "  return {{\n    schema: CELLSCRIPT_BUILDER_SCHEMA,\n    state: \"GeneratedActionPlan\",\n    status: \"requires-runtime-resolution\",\n    action,\n    params,\n    options,\n    metadataHash: {},\n    artifactHash: {},\n    targetProfile: {},\n    canSubmit: false,\n    requiresLiveCellResolution: true,\n    requiresDeploymentResolution: true,\n    cellDataCodecManifest,\n    temporalContract,\n    runtimeAccessProvenanceContract,\n    signingMessageDomains,\n    runtimeAccesses: [...actionSpec.runtimeAccesses],\n    runtimeInputRequirements: [...actionSpec.runtimeInputRequirements],\n    actionScanSelectors: actionSpec.actionScanSelectors as ActionScanSelectors,\n    verifierObligations: [...actionSpec.verifierObligations],\n    failClosedRuntimeFeatures: [...actionSpec.failClosedRuntimeFeatures],\n    notProvenByGeneratedBuilder: [\n      \"live_cell_availability\",\n      \"deployment_live_chain_match\",\n      \"capacity_fee_balance\",\n      \"signature_authority\",\n      \"ckb_vm_execution\",\n      \"cell_data_codec_materialization\",\n      \"tx_pool_acceptance\",\n      \"submission\"\n    ] as const,\n  }};\n}}\n\n",
        typescript_string_literal(metadata_hash),
        metadata.artifact_hash.as_deref().map(typescript_string_literal).unwrap_or_else(|| "null".to_string()),
        typescript_string_literal(&metadata.target_profile.name)
    ));

    ts.push_str(
        "function assertRuntimeObject(value: unknown, label: string): Record<string, unknown> {\n\
           if (typeof value !== \"object\" || value === null || Array.isArray(value)) {\n\
             throw new Error(\"CellScript runtime builder-shape mismatch: \" + label + \" must be an object\");\n\
           }\n\
           return value as Record<string, unknown>;\n\
         }\n\n\
         function assertLiveCellResolutionResult<P extends CellScriptParams>(value: unknown, plan: ActionBuilderPlan<P>): LiveCellResolutionResult {\n\
           const record = assertRuntimeObject(value, \"resolveLiveCells result\");\n\
           for (const field of [\"inputs\", \"referenceInputs\", \"cellDeps\", \"headerDeps\", \"lineage\"] as const) {\n\
             const candidate = record[field];\n\
             if (candidate !== undefined && !Array.isArray(candidate)) {\n\
               throw new Error(\"CellScript runtime builder-shape mismatch: resolveLiveCells.\" + field + \" must be an array when present\");\n\
             }\n\
           }\n\
           assertScanSelectorEvidence(record.scanSelectorEvidence, plan);\n\
           return value as LiveCellResolutionResult;\n\
         }\n\n\
         function assertScanSelectorEvidence<P extends CellScriptParams>(value: unknown, plan: ActionBuilderPlan<P>): void {\n\
           const selectors = actionScanSelectorItems(plan.actionScanSelectors);\n\
           if (selectors.length === 0) {\n\
             if (value !== undefined && !Array.isArray(value)) {\n\
               throw new Error(\"CellScript runtime builder-shape mismatch: resolveLiveCells.scanSelectorEvidence must be an array when present\");\n\
             }\n\
             return;\n\
           }\n\
           if (!Array.isArray(value)) {\n\
             throw new Error(\"CellScript runtime builder-shape mismatch: resolveLiveCells.scanSelectorEvidence is required for action scan selectors\");\n\
           }\n\
           if (value.length !== selectors.length) {\n\
             throw new Error(\"CellScript runtime builder-shape mismatch: resolveLiveCells.scanSelectorEvidence length \" + value.length + \" does not match actionScanSelectors.selector_count \" + selectors.length);\n\
           }\n\
         const selectorsByIndex = new Map<number, Record<string, unknown>>();\n\
         const declaredSelectorIndexes: number[] = [];\n\
         selectors.forEach((selector, fallbackIndex) => {\n\
           const index = selectorIndex(selector, fallbackIndex);\n\
           if (selectorsByIndex.has(index)) {\n\
             throw new Error(\"CellScript runtime builder-shape mismatch: actionScanSelectors contains duplicate selector_index \" + index);\n\
           }\n\
           selectorsByIndex.set(index, selector);\n\
           declaredSelectorIndexes.push(index);\n\
         });\n\
         const seenEvidenceIndexes = new Set<number>();\n\
         for (const item of value) {\n\
           const evidence = assertRuntimeObject(item, \"scanSelectorEvidence item\");\n\
           const rawIndex = evidence.selector_index;\n\
           if (typeof rawIndex !== \"number\" || !Number.isInteger(rawIndex)) {\n\
             throw new Error(\"CellScript runtime builder-shape mismatch: scanSelectorEvidence.selector_index must be an integer\");\n\
           }\n\
           if (seenEvidenceIndexes.has(rawIndex)) {\n\
             throw new Error(\"CellScript runtime builder-shape mismatch: scanSelectorEvidence contains duplicate selector_index \" + rawIndex);\n\
           }\n\
           const selector = selectorsByIndex.get(rawIndex);\n\
           if (!selector) {\n\
             throw new Error(\"CellScript runtime builder-shape mismatch: scanSelectorEvidence selector_index \" + rawIndex + \" is not declared by actionScanSelectors\");\n\
           }\n\
           seenEvidenceIndexes.add(rawIndex);\n\
           if (evidence.status !== \"resolved\") {\n\
             throw new Error(\"CellScript runtime builder-shape mismatch: scanSelectorEvidence.status for selector \" + rawIndex + \" must be 'resolved'\");\n\
           }\n\
             assertSelectorEvidenceField(evidence, selector, \"source\", \"ckb_source\", rawIndex);\n\
             assertSelectorEvidenceField(evidence, selector, \"role\", \"role\", rawIndex);\n\
             assertSelectorEvidenceField(evidence, selector, \"binding\", \"binding\", rawIndex);\n\
             assertSelectorEvidenceField(evidence, selector, \"feature\", \"feature\", rawIndex);\n\
           assertSelectorEvidenceField(evidence, selector, \"component\", \"component\", rawIndex);\n\
           assertSelectorEvidenceField(evidence, selector, \"script_field\", \"script_field\", rawIndex);\n\
         }\n\
         for (const index of declaredSelectorIndexes) {\n\
           if (!seenEvidenceIndexes.has(index)) {\n\
             throw new Error(\"CellScript runtime builder-shape mismatch: scanSelectorEvidence is missing selector_index \" + index);\n\
           }\n\
         }\n\
       }\n\n\
         function actionScanSelectorItems(actionScanSelectors: ActionScanSelectors): Record<string, unknown>[] {\n\
           const selectors = actionScanSelectors.selectors;\n\
           return Array.isArray(selectors) ? selectors.filter(isRuntimeRecord) : [];\n\
         }\n\n\
         function isRuntimeRecord(value: unknown): value is Record<string, unknown> {\n\
           return typeof value === \"object\" && value !== null && !Array.isArray(value);\n\
         }\n\n\
         function selectorIndex(selector: Record<string, unknown>, fallbackIndex: number): number {\n\
           const value = selector.selector_index;\n\
           return typeof value === \"number\" && Number.isInteger(value) ? value : fallbackIndex;\n\
         }\n\n\
         function assertSelectorEvidenceField(\n\
           evidence: Record<string, unknown>,\n\
           selector: Record<string, unknown>,\n\
           evidenceField: string,\n\
           selectorField: string,\n\
           selectorIndex: number,\n\
         ): void {\n\
         const expected = selector[selectorField];\n\
         const actual = evidence[evidenceField];\n\
         if (expected === undefined || expected === null) {\n\
           if (actual !== undefined && actual !== null) {\n\
             throw new Error(\"CellScript runtime builder-shape mismatch: scanSelectorEvidence.\" + evidenceField + \" unexpected for selector \" + selectorIndex);\n\
           }\n\
           return;\n\
         }\n\
         if (actual === undefined || actual === null) {\n\
           throw new Error(\"CellScript runtime builder-shape mismatch: scanSelectorEvidence.\" + evidenceField + \" missing for selector \" + selectorIndex);\n\
         }\n\
         if (actual !== expected) {\n\
           throw new Error(\"CellScript runtime builder-shape mismatch: scanSelectorEvidence.\" + evidenceField + \" mismatch for selector \" + selectorIndex);\n\
         }\n\
         }\n\n\
         function assertBuiltTransaction(value: unknown): unknown {\n\
           if (value === undefined || value === null) {\n\
             throw new Error(\"CellScript runtime builder-shape mismatch: buildTransaction returned no transaction\");\n\
           }\n\
           return value;\n\
         }\n\n\
         function submittedTxHashFromRuntime(submitResult: unknown): string | null {\n\
           if (typeof submitResult === \"string\") {\n\
             return submitResult;\n\
           }\n\
           if (typeof submitResult === \"object\" && submitResult !== null) {\n\
             const record = submitResult as Record<string, unknown>;\n\
             if (typeof record.txHash === \"string\") {\n\
               return record.txHash;\n\
             }\n\
             if (typeof record.hash === \"string\") {\n\
               return record.hash;\n\
             }\n\
           }\n\
           return null;\n\
         }\n\n",
    );

    ts.push_str("export function createActionBuilder(runtime: CellScriptBuilderRuntime) {\n  return {\n");
    for action in actions {
        let method = typescript_identifier(&action.name, "action");
        let suffix = typescript_type_suffix(&action.name);
        let params_type = typescript_action_params_type(action);
        ts.push_str(&format!(
            "    async {method}(params: {params_type}, options: BuildOptions = {{}}) {{\n      \
             const plan = plan{suffix}(params, options);\n      \
             return executeActionBuilderPlan(runtime, plan, options);\n    }},\n"
        ));
    }
    ts.push_str(
        "  };\n}\n\n\
         async function executeActionBuilderPlan<P extends CellScriptParams>(\n\
           runtime: CellScriptBuilderRuntime,\n\
           plan: ActionBuilderPlan<P>,\n\
           options: BuildOptions,\n\
         ): Promise<ActionBuilderResult<P>> {\n\
           const liveCellResolution = assertLiveCellResolutionResult(await runtime.resolveLiveCells({ plan, options }), plan);\n\
           const transaction = assertBuiltTransaction(await runtime.buildTransaction({ ...plan, liveCellResolution }));\n\
           const result: ActionBuilderResult<P> = {\n\
             schema: CELLSCRIPT_BUILDER_SCHEMA,\n\
             state: \"ActionBuilderResult\",\n\
             status: \"built-by-runtime\",\n\
             mode: \"build\",\n\
             plan,\n\
             liveCellResolution,\n\
             transaction,\n\
             canSubmit: false,\n\
             notProvenByGeneratedBuilder: plan.notProvenByGeneratedBuilder,\n\
           };\n\
           if (options.dryRun || options.submit) {\n\
             if (!runtime.dryRun) {\n\
               throw new Error(\"CellScript builder runtime missing dryRun adapter\");\n\
             }\n\
             result.dryRunResult = await runtime.dryRun(transaction);\n\
             result.status = \"dry-run-by-runtime\";\n\
             result.mode = \"dry-run\";\n\
           }\n\
           if (options.submit) {\n\
             if (!runtime.submit) {\n\
               throw new Error(\"CellScript builder runtime missing submit adapter\");\n\
             }\n\
             result.submitResult = await runtime.submit(transaction);\n\
             result.submittedTxHash = submittedTxHashFromRuntime(result.submitResult);\n\
             result.status = \"submitted-by-runtime\";\n\
             result.mode = \"submit\";\n\
           }\n\
           return result;\n\
         }\n",
    );

    if let Some(policy) = &metadata.runtime.policy_artifact {
        // The existing typed runtime contract remains intact. Its plan now
        // carries an explicit outer-envelope obligation for policy artifacts.
        ts = ts.replace("canSubmit: false;\n", "canSubmit: false;\n  policyWitness?: Readonly<Record<string, unknown>>;\n");
        ts = ts.replace(
            "    state: \"GeneratedActionPlan\",\n",
            "    state: \"GeneratedActionPlan\",\n    policyWitness: policyWitnessRequest(action),\n",
        );
        ts = ts.replace("edition: \"2026\";", "edition: \"2026\" | \"2027\";");
        ts.push_str(&format!("\nexport const policyArtifact = {} as const;\n", json_string_pretty("policy artifact", policy)?));
        let tags = actions
            .iter()
            .map(|action| {
                let variant = policy.declaration.action(&action.name).expect("selected exported action");
                (action.name.clone(), serde_json::json!({ "tag": variant.tag, "requiresArgs": action_requires_entry_witness(action) }))
            })
            .collect::<BTreeMap<_, _>>();
        ts.push_str(&format!(
            "const POLICY_VARIANTS: Readonly<Record<string, {{ tag: number; requiresArgs: boolean }}>> = Object.freeze(JSON.parse({}));\n",
            typescript_string_literal(&json_string_pretty("policy variants", &tags)?)
        ));
        ts.push_str(include_str!("policy_builder.ts"));
    }
    Ok(ts)
}

fn typescript_builder_test(actions: &[&crate::ActionMetadata]) -> Result<String> {
    let cases = actions
        .iter()
        .map(|action| {
            serde_json::json!({
                "name": action.name,
                "plan": format!("plan{}", typescript_type_suffix(&action.name)),
                "method": typescript_identifier(&action.name, "action"),
                "params": javascript_sample_params(action),
            })
        })
        .collect::<Vec<_>>();
    let cases_json = json_string_pretty("builder test cases", &cases)?;
    let dynamic_index_cases = actions
        .iter()
        .flat_map(|action| {
            action.ckb_runtime_accesses.iter().filter_map(|access| {
                let index = &access.provenance.index;
                if index.kind != "dynamic" {
                    return None;
                }
                let binding = index.binding.as_deref()?;
                let max_inclusive = index.max_inclusive?;
                action.params.iter().any(|param| param.name == binding).then(|| {
                    serde_json::json!({
                        "name": action.name,
                        "plan": format!("plan{}", typescript_type_suffix(&action.name)),
                        "binding": binding,
                        "maxInclusive": max_inclusive,
                    })
                })
            })
        })
        .collect::<Vec<_>>();
    let dynamic_index_cases = dynamic_index_cases
        .into_iter()
        .fold(BTreeMap::<(String, String), serde_json::Value>::new(), |mut unique, value| {
            let key = (
                value["name"].as_str().expect("dynamic index action name").to_string(),
                value["binding"].as_str().expect("dynamic index binding").to_string(),
            );
            unique.entry(key).or_insert(value);
            unique
        })
        .into_values()
        .collect::<Vec<_>>();
    let dynamic_index_cases_json = json_string_pretty("dynamic source-index builder test cases", &dynamic_index_cases)?;

    let mut js = String::new();
    js.push_str("import assert from \"node:assert/strict\";\n");
    js.push_str("import test from \"node:test\";\n");
    js.push_str("import * as builder from \"../dist/index.js\";\n\n");
    js.push_str(&format!("const actionCases = {cases_json};\n"));
    js.push_str(&format!("const dynamicIndexCases = {dynamic_index_cases_json};\n"));
    js.push_str("const WRONG_HASH = \"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\";\n\n");
    js.push_str(
        "function selectorEvidenceForPlan(plan) {\n\
           const selectors = Array.isArray(plan.actionScanSelectors?.selectors) ? plan.actionScanSelectors.selectors : [];\n\
           return selectors.map((selector, fallbackIndex) => ({\n\
             selector_index: Number.isInteger(selector.selector_index) ? selector.selector_index : fallbackIndex,\n\
             status: \"resolved\",\n\
             source: selector.ckb_source,\n\
             role: selector.role,\n\
             binding: selector.binding,\n\
             feature: selector.feature,\n\
             component: selector.component,\n\
             script_field: selector.script_field,\n\
           }));\n\
         }\n\n",
    );
    js.push_str(
        "test(\"plans all generated actions without submitting\", () => {\n\
           for (const actionCase of actionCases) {\n\
             const plan = builder[actionCase.plan](actionCase.params);\n\
             assert.equal(plan.schema, builder.CELLSCRIPT_BUILDER_SCHEMA);\n\
             assert.equal(plan.state, \"GeneratedActionPlan\");\n\
             assert.equal(plan.status, \"requires-runtime-resolution\");\n\
             assert.equal(plan.action, actionCase.name);\n\
             assert.equal(plan.canSubmit, false);\n\
             assert.equal(plan.requiresLiveCellResolution, true);\n\
             assert.equal(plan.requiresDeploymentResolution, true);\n\
             assert.equal(plan.actionScanSelectors.schema, builder.ACTION_SCAN_SELECTORS_SCHEMA);\n\
             assert.equal(plan.actionScanSelectors.source, \"transaction_runtime_input_requirements\");\n\
             assert.equal(plan.runtimeInputRequirements.length, plan.actionScanSelectors.selector_count);\n\
             assert.deepEqual(plan.params, actionCase.params);\n\
           }\n\
         });\n\n\
         test(\"rejects dynamic source indexes above their declared bound\", () => {\n\
           for (const dynamicCase of dynamicIndexCases) {\n\
             const actionCase = actionCases.find((candidate) => candidate.name === dynamicCase.name);\n\
             assert.ok(actionCase);\n\
             const params = { ...actionCase.params, [dynamicCase.binding]: BigInt(dynamicCase.maxInclusive) + 1n };\n\
             assert.throws(() => builder[dynamicCase.plan](params), /exceeds max_inclusive/);\n\
           }\n\
         });\n\n\
         test(\"delegates live-cell resolution and transaction build to runtime\", async () => {\n\
           const [first] = actionCases;\n\
           const calls = [];\n\
           const runtime = {\n\
             async resolveLiveCells(request) {\n\
               calls.push([\"resolveLiveCells\", request.plan.action]);\n\
               assert.equal(request.plan.actionScanSelectors.schema, builder.ACTION_SCAN_SELECTORS_SCHEMA);\n\
               assert.equal(request.plan.actionScanSelectors.source, \"transaction_runtime_input_requirements\");\n\
               return { inputs: [\"input-0\"], cellDeps: [\"dep-0\"], lineage: [], scanSelectorEvidence: selectorEvidenceForPlan(request.plan) };\n\
             },\n\
             async buildTransaction(plan) {\n\
               calls.push([\"buildTransaction\", plan.action]);\n\
               return { action: plan.action, inputs: plan.liveCellResolution.inputs };\n\
             },\n\
           };\n\
           const api = builder.createActionBuilder(runtime);\n\
           const result = await api[first.method](first.params);\n\
           assert.equal(result.state, \"ActionBuilderResult\");\n\
           assert.equal(result.status, \"built-by-runtime\");\n\
           assert.equal(result.mode, \"build\");\n\
           assert.equal(result.plan.action, first.name);\n\
           assert.equal(result.transaction.action, first.name);\n\
           assert.deepEqual(result.liveCellResolution.inputs, [\"input-0\"]);\n\
           assert.deepEqual(calls, [[\"resolveLiveCells\", first.name], [\"buildTransaction\", first.name]]);\n\
         });\n\n\
         test(\"delegates dry-run and submit modes to runtime\", async () => {\n\
           const [first] = actionCases;\n\
           const calls = [];\n\
           const runtime = {\n\
             async resolveLiveCells(request) {\n\
               calls.push([\"resolveLiveCells\", request.plan.action]);\n\
               return { inputs: [\"input-0\"], cellDeps: [\"dep-0\"], lineage: [], scanSelectorEvidence: selectorEvidenceForPlan(request.plan) };\n\
             },\n\
             async buildTransaction(plan) {\n\
               calls.push([\"buildTransaction\", plan.action]);\n\
               return { action: plan.action, built: true };\n\
             },\n\
             async dryRun(transaction) {\n\
               calls.push([\"dryRun\", transaction.action]);\n\
               return { cycles: 42, exitCode: 0 };\n\
             },\n\
             async submit(transaction) {\n\
               calls.push([\"submit\", transaction.action]);\n\
               return { txHash: \"0x1234\" };\n\
             },\n\
           };\n\
           const api = builder.createActionBuilder(runtime);\n\
           const dryRunResult = await api[first.method](first.params, { dryRun: true });\n\
           assert.equal(dryRunResult.mode, \"dry-run\");\n\
           assert.deepEqual(dryRunResult.dryRunResult, { cycles: 42, exitCode: 0 });\n\
           calls.length = 0;\n\
           const submitResult = await api[first.method](first.params, { submit: true });\n\
           assert.equal(submitResult.mode, \"submit\");\n\
           assert.equal(submitResult.submittedTxHash, \"0x1234\");\n\
           assert.deepEqual(calls, [\n\
             [\"resolveLiveCells\", first.name],\n\
             [\"buildTransaction\", first.name],\n\
             [\"dryRun\", first.name],\n\
             [\"submit\", first.name],\n\
           ]);\n\
         });\n\n\
         test(\"rejects missing runtime adapters and malformed runtime shapes\", async () => {\n\
           const [first] = actionCases;\n\
           const firstPlan = builder[first.plan](first.params);\n\
           const noDryRunRuntime = {\n\
             async resolveLiveCells(request) { return { inputs: [], scanSelectorEvidence: selectorEvidenceForPlan(request.plan) }; },\n\
             async buildTransaction() { return { tx: true }; },\n\
           };\n\
           const badShapeRuntime = {\n\
             async resolveLiveCells() { return { inputs: \"not-an-array\" }; },\n\
             async buildTransaction() { return { tx: true }; },\n\
           };\n\
           const missingSelectorEvidenceRuntime = {\n\
             async resolveLiveCells() { return { inputs: [] }; },\n\
             async buildTransaction() { return { tx: true }; },\n\
           };\n\
         const mismatchedSelectorEvidenceRuntime = {\n\
           async resolveLiveCells(request) {\n\
             const evidence = selectorEvidenceForPlan(request.plan);\n\
             if (evidence.length > 0) {\n\
               evidence[0] = { ...evidence[0], role: \"wrong-role\" };\n\
             }\n\
             return { inputs: [], scanSelectorEvidence: evidence };\n\
           },\n\
           async buildTransaction() { return { tx: true }; },\n\
         };\n\
         const missingSelectorFieldRuntime = {\n\
           async resolveLiveCells(request) {\n\
             const evidence = selectorEvidenceForPlan(request.plan);\n\
             if (evidence.length > 0) {\n\
               delete evidence[0].source;\n\
             }\n\
             return { inputs: [], scanSelectorEvidence: evidence };\n\
           },\n\
           async buildTransaction() { return { tx: true }; },\n\
         };\n\
         const duplicateSelectorEvidenceRuntime = {\n\
           async resolveLiveCells(request) {\n\
             const evidence = selectorEvidenceForPlan(request.plan);\n\
             if (evidence.length > 1) {\n\
               evidence[1] = { ...evidence[0] };\n\
             }\n\
             return { inputs: [], scanSelectorEvidence: evidence };\n\
           },\n\
           async buildTransaction() { return { tx: true }; },\n\
         };\n\
         await assert.rejects(\n\
           () => builder.createActionBuilder(noDryRunRuntime)[first.method](first.params, { dryRun: true }),\n\
           /missing dryRun adapter/,\n\
           );\n\
           await assert.rejects(\n\
             () => builder.createActionBuilder(badShapeRuntime)[first.method](first.params),\n\
             /builder-shape mismatch/,\n\
           );\n\
           if ((firstPlan.actionScanSelectors.selectors ?? []).length > 0) {\n\
             await assert.rejects(\n\
               () => builder.createActionBuilder(missingSelectorEvidenceRuntime)[first.method](first.params),\n\
               /scanSelectorEvidence/,\n\
             );\n\
           await assert.rejects(\n\
             () => builder.createActionBuilder(mismatchedSelectorEvidenceRuntime)[first.method](first.params),\n\
             /scanSelectorEvidence.role mismatch/,\n\
           );\n\
           await assert.rejects(\n\
             () => builder.createActionBuilder(missingSelectorFieldRuntime)[first.method](first.params),\n\
             /scanSelectorEvidence.source missing/,\n\
           );\n\
           if ((firstPlan.actionScanSelectors.selectors ?? []).length > 1) {\n\
             await assert.rejects(\n\
               () => builder.createActionBuilder(duplicateSelectorEvidenceRuntime)[first.method](first.params),\n\
               /duplicate selector_index/,\n\
             );\n\
           }\n\
         }\n\
       });\n\n\
         test(\"maps runtime errors to action field context\", () => {\n\
           const [first] = actionCases;\n\
           const context = builder.runtimeErrorContextForAction(first.name);\n\
           assert.equal(context.action, first.name);\n\
           assert.equal(context.fields.length, Object.keys(first.params).length);\n\
           const byCode = builder.runtimeErrorInfoByCode(25);\n\
           assert.equal(byCode.name, \"entry-witness-abi-invalid\");\n\
           const fromObject = builder.explainCellScriptRuntimeError({ exitCode: 25 }, first.name);\n\
           assert.equal(fromObject.code, 25);\n\
           assert.equal(fromObject.action, first.name);\n\
           assert.equal(fromObject.actionFields.length, context.fields.length);\n\
           const fromMessage = builder.explainCellScriptRuntimeError({ message: \"entry witness payload layout failed\" }, first.name);\n\
           assert.equal(fromMessage.name, \"entry-witness-abi-invalid\");\n\
           assert.equal(builder.explainCellScriptRuntimeError({ exitCode: 999999 }, first.name), null);\n\
         });\n\n\
         test(\"rejects mismatched lockfile identity\", () => {\n\
           const [first] = actionCases;\n\
           const badLockfile = {\n\
             package: { source_hash: WRONG_HASH },\n\
             package_build: {\n\
               compiler_version: \"wrong-compiler\",\n\
               target_profile: builder.builderManifest.target_profile,\n\
               artifact_hash: builder.builderManifest.artifact_hash,\n\
               metadata_hash: builder.builderManifest.metadata_hash,\n\
             },\n\
           };\n\
           assert.throws(\n\
             () => builder[first.plan](first.params, { lockfile: badLockfile }),\n\
             /CellScript builder identity mismatch/,\n\
           );\n\
         });\n\n\
         test(\"rejects mismatched deployment identity when deployment binding is embedded\", () => {\n\
           const [first] = actionCases;\n\
           const deployment = builder.builderManifest.deployment_identity?.deployments?.[0];\n\
           if (!deployment) {\n\
             assert.deepEqual(builder.validateCellScriptDeployment(undefined, undefined), []);\n\
             assert.deepEqual(builder.validateCellScriptDeploymentTrust(undefined, undefined), []);\n\
             assert.deepEqual(\n\
               builder.validateCellScriptDeploymentTrust(undefined, { requirePublisherSignature: true }),\n\
               [\"trust policy requires a deployment record\"],\n\
             );\n\
             assert.throws(\n\
               () => builder[first.plan](first.params, { trustPolicy: { requirePublisherSignature: true } }),\n\
               /trust policy requires a deployment record/,\n\
             );\n\
             return;\n\
           }\n\
           const badDeployment = { ...deployment, code_hash: WRONG_HASH };\n\
           assert.throws(\n\
             () => builder[first.plan](first.params, { deployment: badDeployment }),\n\
             /CellScript deployment identity mismatch/,\n\
           );\n\
           const deprecatedDeployment = { ...deployment, status: \"deprecated\" };\n\
           assert.throws(\n\
             () => builder[first.plan](first.params, { deployment: deprecatedDeployment }),\n\
             /deployment status/,\n\
           );\n\
           const { status: _deploymentStatus, ...missingStatusDeployment } = deployment;\n\
           assert.throws(\n\
             () => builder[first.plan](first.params, { deployment: missingStatusDeployment }),\n\
             /no status/,\n\
           );\n\
           const { publisher_signature: _publisherSignature, audit_report_hash: _auditReportHash, ...unsignedDeployment } = deployment;\n\
           assert.throws(\n\
             () => builder[first.plan](first.params, { deployment: unsignedDeployment, trustPolicy: { requirePublisherSignature: true } }),\n\
             /publisher_signature/,\n\
           );\n\
           const signedDeployment = { ...deployment, publisher_signature: \"sig:fixture\", audit_report_hash: \"0xaaa\" };\n\
           assert.deepEqual(\n\
             builder.validateCellScriptDeploymentTrust(signedDeployment, { requirePublisherSignature: true, requireAuditReportHash: true }),\n\
             [],\n\
           );\n\
           assert.throws(\n\
             () => builder[first.plan](first.params, {\n\
               deployment,\n\
               liveDeploymentEvidence: {\n\
                 status: \"failed\",\n\
                 deployment_status: \"deprecated\",\n\
                 rpc_status: \"dead\",\n\
                 out_point: deployment.out_point,\n\
                 rpc_data_hash: deployment.data_hash,\n\
                 rpc_code_hash: deployment.code_hash,\n\
                 violations: [\"deployment for network 'aggron4' is not active: Deprecated\"],\n\
               },\n\
             }),\n\
             /CellScript deployment identity mismatch/,\n\
           );\n\
         });\n",
    );
    Ok(js)
}

fn javascript_sample_params(action: &crate::ActionMetadata) -> serde_json::Value {
    let mut params = serde_json::Map::new();
    for param in &action.params {
        params.insert(param.name.clone(), javascript_sample_param_value(param));
    }
    serde_json::Value::Object(params)
}

fn javascript_sample_param_value(param: &ParamMetadata) -> serde_json::Value {
    if param.schema_pointer_abi
        || param.schema_length_abi
        || param.ty == "Address"
        || param.ty == "Hash"
        || param.fixed_byte_len.is_some()
    {
        let bytes = param.fixed_byte_len.unwrap_or(if param.ty == "Address" || param.ty == "Hash" { 32 } else { 0 });
        return serde_json::Value::String(format!("0x{}", "00".repeat(bytes)));
    }

    match param.ty.as_str() {
        "bool" => serde_json::Value::Bool(false),
        "u8" | "u16" | "u32" | "u64" | "u128" | "i8" | "i16" | "i32" | "i64" | "i128" => serde_json::json!(0),
        temporal if crate::ir::is_ckb_temporal_scalar_name(temporal) => serde_json::json!(0),
        "()" => serde_json::Value::Null,
        _ => serde_json::Value::String("0x".to_string()),
    }
}

fn default_builder_package_name(metadata: &CompileMetadata) -> String {
    let module = metadata.module.replace("::", "-").replace('_', "-");
    let trimmed = module.trim_matches('-');
    if trimmed.is_empty() {
        "@cellscript/generated-builder".to_string()
    } else {
        format!("@cellscript/{}-builder", trimmed.to_ascii_lowercase())
    }
}

fn typescript_action_params_type(action: &crate::ActionMetadata) -> String {
    format!("{}Params", typescript_type_suffix(&action.name))
}

fn typescript_type_suffix(name: &str) -> String {
    let mut output = String::new();
    let mut uppercase_next = true;
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            if uppercase_next {
                output.push(ch.to_ascii_uppercase());
                uppercase_next = false;
            } else {
                output.push(ch);
            }
        } else {
            uppercase_next = true;
        }
    }
    if output.is_empty() || output.chars().next().is_some_and(|ch| ch.is_ascii_digit()) {
        output.insert_str(0, "Action");
    }
    output
}

fn typescript_identifier(name: &str, fallback: &str) -> String {
    let mut ident = String::new();
    for (index, ch) in name.chars().enumerate() {
        if ch == '_' || ch == '$' || ch.is_ascii_alphabetic() || (index > 0 && ch.is_ascii_digit()) {
            ident.push(ch);
        } else if ch.is_ascii_digit() && index == 0 {
            ident.push('_');
            ident.push(ch);
        } else {
            ident.push('_');
        }
    }
    if ident.is_empty() || TYPESCRIPT_RESERVED_WORDS.contains(&ident.as_str()) {
        format!("{}_{}", fallback, crate::hex_encode(&crate::ckb_blake2b256(name.as_bytes()))[..8].to_ascii_lowercase())
    } else {
        ident
    }
}

fn typescript_object_key(name: &str) -> String {
    let ident = typescript_identifier(name, "param");
    if ident == name {
        ident
    } else {
        typescript_string_literal(name)
    }
}

fn typescript_param_type(param: &ParamMetadata) -> &str {
    if param.schema_pointer_abi
        || param.schema_length_abi
        || param.fixed_byte_len.is_some()
        || param.ty == "Address"
        || param.ty == "Hash"
    {
        return "HexString | Uint8Array";
    }

    match param.ty.as_str() {
        "bool" => "boolean",
        "u8" | "u16" | "u32" | "u64" | "u128" | "i8" | "i16" | "i32" | "i64" | "i128" => "bigint | number | string",
        temporal if crate::ir::is_ckb_temporal_scalar_name(temporal) => temporal,
        "()" => "null | undefined",
        _ => "CellScriptValue",
    }
}

fn typescript_string_literal(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_string())
}

fn json_bytes_pretty<T: serde::Serialize>(label: &str, value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec_pretty(value)
        .map_err(|error| crate::error::CompileError::without_span(format!("failed to serialize {label}: {error}")))
}

fn json_string_pretty<T: serde::Serialize>(label: &str, value: &T) -> Result<String> {
    serde_json::to_string_pretty(value)
        .map_err(|error| crate::error::CompileError::without_span(format!("failed to serialize {label}: {error}")))
}

const TYPESCRIPT_RESERVED_WORDS: &[&str] = &[
    "break",
    "case",
    "catch",
    "class",
    "const",
    "continue",
    "debugger",
    "default",
    "delete",
    "do",
    "else",
    "enum",
    "export",
    "extends",
    "false",
    "finally",
    "for",
    "function",
    "if",
    "import",
    "in",
    "instanceof",
    "new",
    "null",
    "return",
    "super",
    "switch",
    "this",
    "throw",
    "true",
    "try",
    "typeof",
    "var",
    "void",
    "while",
    "with",
    "as",
    "implements",
    "interface",
    "let",
    "package",
    "private",
    "protected",
    "public",
    "static",
    "yield",
];

fn ckb_fixture_manifest_report(manifest: &serde_json::Value, base_dir: &Path, manifest_bytes: &[u8]) -> serde_json::Value {
    let mut issues = Vec::<String>::new();
    let mut rows = Vec::<serde_json::Value>::new();
    let manifest_hash = crate::hex_encode(&crate::ckb_blake2b256(manifest_bytes));

    match manifest["schema"].as_str() {
        Some(CKB_STANDARD_COMPAT_MANIFEST_SCHEMA) => {}
        Some(ICKB_CLAIM_MANIFEST_SCHEMA) => return ickb_claim_manifest_report(manifest, base_dir, manifest_bytes),
        got => {
            issues.push(format!(
                "manifest schema must be {CKB_STANDARD_COMPAT_MANIFEST_SCHEMA} or {ICKB_CLAIM_MANIFEST_SCHEMA}, got {}",
                got.unwrap_or("<missing>")
            ));
            return ckb_fixture_report_json(manifest, manifest_hash, 0, rows, issues);
        }
    }

    let Some(suites) = manifest["suites"].as_array() else {
        issues.push("manifest suites must be an array".to_string());
        return ckb_fixture_report_json(manifest, manifest_hash, 0, rows, issues);
    };

    for suite in suites {
        validate_ckb_fixture_suite(suite, base_dir, &mut rows, &mut issues);
    }

    ckb_fixture_report_json(manifest, manifest_hash, suites.len(), rows, issues)
}

fn ickb_claim_manifest_report(manifest: &serde_json::Value, base_dir: &Path, manifest_bytes: &[u8]) -> serde_json::Value {
    let mut issues = Vec::<String>::new();
    let mut rows = Vec::<serde_json::Value>::new();
    let manifest_hash = crate::hex_encode(&crate::ckb_blake2b256(manifest_bytes));

    if manifest["schema"].as_str() != Some(ICKB_CLAIM_MANIFEST_SCHEMA) {
        issues.push(format!(
            "iCKB claim manifest schema must be {ICKB_CLAIM_MANIFEST_SCHEMA}, got {}",
            manifest["schema"].as_str().unwrap_or("<missing>")
        ));
    }

    let matrix_path = match manifest["matrix_path"].as_str() {
        Some(path) if !path.is_empty() => base_dir.join(path),
        _ => {
            issues.push("iCKB claim manifest matrix_path must be a non-empty string".to_string());
            return ckb_fixture_report_json(manifest, manifest_hash, 0, rows, issues);
        }
    };

    let matrix_bytes = match std::fs::read(&matrix_path) {
        Ok(bytes) => bytes,
        Err(err) => {
            issues.push(format!("failed to read iCKB matrix {}: {err}", matrix_path.display()));
            return ckb_fixture_report_json(manifest, manifest_hash, 0, rows, issues);
        }
    };
    let matrix: serde_json::Value = match serde_json::from_slice(&matrix_bytes) {
        Ok(matrix) => matrix,
        Err(err) => {
            issues.push(format!("failed to parse iCKB matrix {}: {err}", matrix_path.display()));
            return ckb_fixture_report_json(manifest, manifest_hash, 0, rows, issues);
        }
    };

    validate_ickb_claim_matrix(&matrix, &mut issues);

    let mut matrix_rows = BTreeMap::<String, &serde_json::Value>::new();
    if let Some(active_rows) = matrix["rows"].as_array() {
        for row in active_rows {
            if let Some(scenario) = row["scenario"].as_str() {
                if matrix_rows.insert(scenario.to_string(), row).is_some() {
                    issues.push(format!("iCKB matrix contains duplicate scenario {scenario}"));
                }
            } else {
                issues.push("iCKB matrix row missing scenario".to_string());
            }
        }
    } else {
        issues.push("iCKB matrix rows must be an array".to_string());
    }

    let default_production = manifest.get("default_production_evidence");
    let default_hardening = manifest.get("default_hardening");
    let Some(families) = manifest["families"].as_array() else {
        issues.push("iCKB claim manifest families must be an array".to_string());
        return ckb_fixture_report_json(manifest, manifest_hash, 0, rows, issues);
    };

    for family in families {
        validate_ickb_claim_family(family, &matrix_rows, default_production, default_hardening, &mut rows, &mut issues);
    }

    ckb_fixture_report_json(manifest, manifest_hash, families.len(), rows, issues)
}

fn ckb_fixture_report_json(
    manifest: &serde_json::Value,
    manifest_hash: String,
    suite_count: usize,
    rows: Vec<serde_json::Value>,
    issues: Vec<String>,
) -> serde_json::Value {
    let is_ickb_claim = manifest["schema"].as_str() == Some(ICKB_CLAIM_MANIFEST_SCHEMA);
    let evidence_execution_level = if is_ickb_claim { serde_json::json!(ICKB_DIFF_EVIDENCE_LEVEL) } else { serde_json::Value::Null };
    let required_executable_gate =
        if is_ickb_claim { serde_json::json!("cargo test --locked -p cellscript --test ickb_diff") } else { serde_json::Value::Null };
    serde_json::json!({
        "schema": "cellscript-ckb-fixture-verification-v0.17",
        "manifest_schema": manifest["schema"].as_str().unwrap_or("unknown"),
        "manifest_status": manifest["status"].as_str().unwrap_or("unknown"),
        "manifest_hash": manifest_hash,
        "execution_level": if is_ickb_claim { "DIFFERENTIAL_CKB_VM_MANIFEST" } else { "MODEL" },
        "ckb_vm_execution": false,
        "committed_ckb_vm_evidence": is_ickb_claim,
        "evidence_execution_level": evidence_execution_level,
        "required_executable_gate": required_executable_gate,
        "suite_count": suite_count,
        "fixture_count": rows.len(),
        "status": if issues.is_empty() { "ok" } else { "failed" },
        "issue_count": issues.len(),
        "issues": issues,
        "fixtures": rows,
        "vm_execution_note": if is_ickb_claim {
            "This command does not execute CKB VM. It validates the iCKB claim manifest against committed dual-side CKB VM differential rows, production evidence envelopes, and the required executable Rust gate."
        } else {
            "This command validates transaction-shape model fixtures only; it does not execute CKB VM or prove production compatibility."
        },
    })
}

fn validate_ickb_claim_matrix(matrix: &serde_json::Value, issues: &mut Vec<String>) {
    if matrix["schema"].as_str() != Some(ICKB_DIFF_MATRIX_SCHEMA) {
        issues.push(format!(
            "iCKB matrix schema must be {ICKB_DIFF_MATRIX_SCHEMA}, got {}",
            matrix["schema"].as_str().unwrap_or("<missing>")
        ));
    }
    if matrix["mode"].as_str() != Some("EXECUTED_CKB_VM_DIFF") {
        issues.push("iCKB matrix mode must be EXECUTED_CKB_VM_DIFF".to_string());
    }
    if matrix["equivalence_status"].as_str() != Some("PROVEN") {
        issues.push("iCKB matrix equivalence_status must be PROVEN".to_string());
    }
    if matrix["production_equivalence_claim"].as_bool() != Some(true) {
        issues.push("iCKB matrix production_equivalence_claim must be true".to_string());
    }
    if matrix["remaining_model_blockers"].as_array().is_none_or(|blockers| !blockers.is_empty()) {
        issues.push("iCKB matrix remaining_model_blockers must be empty".to_string());
    }
    if matrix["non_executable_model_assumptions"].as_array().is_none_or(|assumptions| !assumptions.is_empty()) {
        issues.push("iCKB matrix non_executable_model_assumptions must be empty".to_string());
    }
}

fn validate_ickb_claim_family(
    family: &serde_json::Value,
    matrix_rows: &BTreeMap<String, &serde_json::Value>,
    default_production: Option<&serde_json::Value>,
    default_hardening: Option<&serde_json::Value>,
    rows: &mut Vec<serde_json::Value>,
    issues: &mut Vec<String>,
) {
    let family_id = family["id"].as_str().unwrap_or("<missing-family>");
    if family["id"].as_str().is_none_or(str::is_empty) {
        issues.push("iCKB claim family id must be a non-empty string".to_string());
    }
    let Some(branches) = family["branches"].as_array() else {
        issues.push(format!("iCKB claim family {family_id} branches must be an array"));
        return;
    };

    for branch in branches {
        validate_ickb_claim_branch(family_id, branch, matrix_rows, default_production, default_hardening, rows, issues);
    }
}

fn validate_ickb_claim_branch(
    family_id: &str,
    branch: &serde_json::Value,
    matrix_rows: &BTreeMap<String, &serde_json::Value>,
    default_production: Option<&serde_json::Value>,
    default_hardening: Option<&serde_json::Value>,
    rows: &mut Vec<serde_json::Value>,
    issues: &mut Vec<String>,
) {
    let branch_id = branch["id"].as_str().unwrap_or("<missing-branch>");
    if branch["id"].as_str().is_none_or(str::is_empty) {
        issues.push(format!("iCKB claim family {family_id} has branch with missing id"));
    }
    let status = branch["status"].as_str().unwrap_or("<missing-status>");
    let mut matched = ickb_claim_branch_scenarios(branch, matrix_rows);

    match status {
        "in_scope" | "fixture_scoped" => {
            validate_ickb_required_scenarios(family_id, branch_id, branch, matrix_rows, &mut matched, issues);
            if matched.is_empty() {
                issues.push(format!("iCKB claim branch {family_id}/{branch_id} has no matching matrix rows"));
            }
            for scenario in &matched {
                if let Some(row) = matrix_rows.get(scenario) {
                    validate_ickb_claim_row(family_id, branch_id, scenario, row, issues);
                }
            }

            let production = branch.get("production_evidence").or(default_production);
            validate_ickb_evidence_object(
                "production_evidence",
                &ICKB_REQUIRED_PRODUCTION_EVIDENCE,
                production,
                family_id,
                branch_id,
                issues,
            );
            let hardening = branch.get("hardening").or(default_hardening);
            validate_ickb_evidence_object("hardening", &ICKB_REQUIRED_HARDENING_EVIDENCE, hardening, family_id, branch_id, issues);
            validate_ickb_claim_thresholds(family_id, branch_id, hardening, &matched, matrix_rows, issues);
            if status == "fixture_scoped" && branch["limitation"].as_str().is_none_or(str::is_empty) {
                issues.push(format!("iCKB fixture-scoped branch {family_id}/{branch_id} must declare limitation"));
            }
        }
        "retired" => {
            if branch["reason"].as_str().is_none_or(str::is_empty) {
                issues.push(format!("iCKB retired branch {family_id}/{branch_id} must declare reason"));
            }
            let replacements = json_string_array(branch, "replacement_scenarios");
            if replacements.is_empty() {
                issues.push(format!("iCKB retired branch {family_id}/{branch_id} must declare replacement_scenarios"));
            }
            for scenario in replacements {
                if !matrix_rows.contains_key(&scenario) {
                    issues.push(format!("iCKB retired branch {family_id}/{branch_id} replacement scenario is missing: {scenario}"));
                }
            }
        }
        "out_of_scope" => {
            if branch["reason"].as_str().is_none_or(str::is_empty) {
                issues.push(format!("iCKB out-of-scope branch {family_id}/{branch_id} must declare reason"));
            }
            if branch["source_evidence"].as_str().is_none_or(str::is_empty) {
                issues.push(format!("iCKB out-of-scope branch {family_id}/{branch_id} must declare source_evidence"));
            }
        }
        other => issues.push(format!("iCKB claim branch {family_id}/{branch_id} has unsupported status {other}")),
    }

    rows.push(serde_json::json!({
        "family": family_id,
        "branch": branch_id,
        "status": status,
        "matched_rows": matched.len(),
        "reject_rows": matched.iter().filter(|scenario| {
            matrix_rows
                .get(*scenario)
                .is_some_and(|row| row["original_ickb_expected"].as_str() == Some("fail") || row["cellscript_expected"].as_str() == Some("fail"))
        }).count(),
        "evidence_level": if matched.is_empty() { "DECLARATIVE" } else { ICKB_DIFF_EVIDENCE_LEVEL },
    }));
}

fn ickb_claim_branch_scenarios(branch: &serde_json::Value, matrix_rows: &BTreeMap<String, &serde_json::Value>) -> BTreeSet<String> {
    let mut matched = BTreeSet::new();
    let excludes = json_string_array(branch, "exclude_scenario_prefixes");
    for scenario in json_string_array(branch, "evidence_scenarios") {
        matched.insert(scenario);
    }
    for prefix in json_string_array(branch, "evidence_scenario_prefixes") {
        for scenario in matrix_rows.keys() {
            if scenario.starts_with(&prefix) && !excludes.iter().any(|exclude| scenario.starts_with(exclude)) {
                matched.insert(scenario.clone());
            }
        }
    }
    matched
}

fn validate_ickb_required_scenarios(
    family_id: &str,
    branch_id: &str,
    branch: &serde_json::Value,
    matrix_rows: &BTreeMap<String, &serde_json::Value>,
    matched: &mut BTreeSet<String>,
    issues: &mut Vec<String>,
) {
    for scenario in json_string_array(branch, "required_scenarios") {
        if matrix_rows.contains_key(&scenario) {
            matched.insert(scenario);
        } else {
            issues.push(format!("iCKB claim branch {family_id}/{branch_id} required scenario is missing: {scenario}"));
        }
    }
}

fn validate_ickb_claim_row(family_id: &str, branch_id: &str, scenario: &str, row: &serde_json::Value, issues: &mut Vec<String>) {
    if row["evidence_level"].as_str() != Some(ICKB_DIFF_EVIDENCE_LEVEL) {
        issues.push(format!(
            "iCKB claim branch {family_id}/{branch_id} scenario {scenario} must have evidence_level={ICKB_DIFF_EVIDENCE_LEVEL}"
        ));
    }
    if row["ckb_vm_execution"].as_bool() != Some(true)
        || row["original_ickb_executed"].as_bool() != Some(true)
        || row["full_differential"].as_bool() != Some(true)
    {
        issues.push(format!("iCKB claim branch {family_id}/{branch_id} scenario {scenario} is not a full dual-side VM row"));
    }
    let original = row["original_ickb_expected"].as_str();
    let cellscript = row["cellscript_expected"].as_str();
    if original != cellscript {
        issues.push(format!(
            "iCKB claim branch {family_id}/{branch_id} scenario {scenario} expectation mismatch original={original:?} cellscript={cellscript:?}"
        ));
    }
    if (original == Some("fail") || cellscript == Some("fail"))
        && row["failure_mode"].as_str().is_none_or(str::is_empty)
        && row["execution"]["failure_mode"].as_str().is_none_or(str::is_empty)
    {
        issues.push(format!("iCKB claim branch {family_id}/{branch_id} reject scenario {scenario} lacks named failure mode"));
    }
    for field in ["tx_size_bytes", "occupied_capacity_shannons", "fee_shannons"] {
        if !row["execution"].get(field).is_some_and(ckb_fixture_non_empty_json_value) {
            issues.push(format!("iCKB claim branch {family_id}/{branch_id} scenario {scenario} execution missing {field}"));
        }
    }
    if !row["execution"]["normalized_fixture"].is_object() {
        issues.push(format!("iCKB claim branch {family_id}/{branch_id} scenario {scenario} missing normalized_fixture"));
    }
    validate_ickb_claim_execution_object(family_id, branch_id, scenario, row, issues);
}

fn validate_ickb_claim_execution_object(
    family_id: &str,
    branch_id: &str,
    scenario: &str,
    row: &serde_json::Value,
    issues: &mut Vec<String>,
) {
    let Some(execution) = row["execution"].as_object() else {
        issues.push(format!("iCKB claim branch {family_id}/{branch_id} scenario {scenario} missing execution object"));
        return;
    };
    for field in [
        "fixture_sha256",
        "normalized_fixture_sha256",
        "transaction_context_sha256",
        "original_ickb_binary_sha256",
        "cellscript_artifact_sha256",
        "ckb_vm_or_testtool_version",
        "original_ickb_exit_code",
        "cellscript_exit_code",
        "original_ickb_status",
        "cellscript_status",
        "statuses_match",
        "original_cycles",
        "cellscript_cycles",
        "tx_size_bytes",
        "occupied_capacity_shannons",
        "fee_shannons",
    ] {
        if !execution.get(field).is_some_and(ckb_fixture_non_empty_json_value) {
            issues.push(format!("iCKB claim branch {family_id}/{branch_id} scenario {scenario} execution missing non-empty {field}"));
        }
    }

    for field in ["fixture_sha256", "normalized_fixture_sha256", "original_ickb_binary_sha256", "cellscript_artifact_sha256"] {
        match execution.get(field).and_then(serde_json::Value::as_str) {
            Some(hash) if ckb_fixture_is_canonical_prefixed_sha256(hash) => {}
            _ => issues.push(format!(
                "iCKB claim branch {family_id}/{branch_id} scenario {scenario} execution.{field} must be canonical 0x-prefixed SHA-256"
            )),
        }
    }

    match execution.get("transaction_context_sha256").and_then(serde_json::Value::as_object) {
        Some(hashes) => {
            for side in ["original", "cellscript"] {
                match hashes.get(side).and_then(serde_json::Value::as_str) {
                    Some(hash) if ckb_fixture_is_canonical_prefixed_sha256(hash) => {}
                    _ => issues.push(format!(
                        "iCKB claim branch {family_id}/{branch_id} scenario {scenario} transaction_context_sha256.{side} must be canonical 0x-prefixed SHA-256"
                    )),
                }
            }
        }
        None => issues.push(format!(
            "iCKB claim branch {family_id}/{branch_id} scenario {scenario} execution.transaction_context_sha256 must be an object"
        )),
    }

    if execution.get("statuses_match").and_then(serde_json::Value::as_bool) != Some(true) {
        issues.push(format!("iCKB claim branch {family_id}/{branch_id} scenario {scenario} execution.statuses_match must be true"));
    }

    for (side, expected_field, status_field, exit_field, cycle_field) in [
        ("original", "original_ickb_expected", "original_ickb_status", "original_ickb_exit_code", "original_cycles"),
        ("cellscript", "cellscript_expected", "cellscript_status", "cellscript_exit_code", "cellscript_cycles"),
    ] {
        let expected = row[expected_field].as_str();
        let status = execution.get(status_field).and_then(serde_json::Value::as_str);
        if expected.is_some() && status != expected {
            issues.push(format!(
                "iCKB claim branch {family_id}/{branch_id} scenario {scenario} {side} status {status:?} does not match {expected_field}={expected:?}"
            ));
        }
        if status == Some("pass") {
            if execution.get(exit_field).and_then(serde_json::Value::as_i64) != Some(0) {
                issues
                    .push(format!("iCKB claim branch {family_id}/{branch_id} scenario {scenario} {side} pass must have exit code 0"));
            }
            if execution.get(cycle_field).and_then(serde_json::Value::as_u64).unwrap_or(0) == 0 {
                issues.push(format!("iCKB claim branch {family_id}/{branch_id} scenario {scenario} {side} pass must consume cycles"));
            }
        }
        if status == Some("fail") && execution.get(exit_field).and_then(serde_json::Value::as_i64) == Some(0) {
            issues.push(format!(
                "iCKB claim branch {family_id}/{branch_id} scenario {scenario} {side} fail must have a non-zero exit code"
            ));
        }
    }

    for field in ["tx_size_bytes", "occupied_capacity_shannons"] {
        if execution.get(field).and_then(serde_json::Value::as_u64).unwrap_or(0) == 0 {
            issues.push(format!("iCKB claim branch {family_id}/{branch_id} scenario {scenario} execution.{field} must be positive"));
        }
    }

    if row["original_ickb_expected"] == "fail" || row["cellscript_expected"] == "fail" {
        match execution.get("failure_mode").and_then(serde_json::Value::as_str) {
            Some(mode) if !mode.is_empty() => {}
            _ => issues.push(format!(
                "iCKB claim branch {family_id}/{branch_id} scenario {scenario} reject case missing execution.failure_mode"
            )),
        }
    }
}

fn validate_ickb_evidence_object(
    label: &str,
    required: &[&str],
    object: Option<&serde_json::Value>,
    family_id: &str,
    branch_id: &str,
    issues: &mut Vec<String>,
) {
    let Some(object) = object.and_then(serde_json::Value::as_object) else {
        issues.push(format!("iCKB claim branch {family_id}/{branch_id} missing {label} object"));
        return;
    };
    for field in required {
        if !object.get(*field).is_some_and(ckb_fixture_non_empty_json_value) {
            issues.push(format!("iCKB claim branch {family_id}/{branch_id} {label} missing non-empty {field}"));
        }
    }
}

fn validate_ickb_claim_thresholds(
    family_id: &str,
    branch_id: &str,
    hardening: Option<&serde_json::Value>,
    scenarios: &BTreeSet<String>,
    matrix_rows: &BTreeMap<String, &serde_json::Value>,
    issues: &mut Vec<String>,
) {
    let max_cycles = hardening.and_then(|value| value["max_cellscript_cycles"].as_u64());
    let max_tx_size = hardening.and_then(|value| value["max_tx_size_bytes"].as_u64());
    for scenario in scenarios {
        let Some(row) = matrix_rows.get(scenario) else {
            continue;
        };
        if let (Some(max), Some(actual)) = (max_cycles, row["execution"]["cellscript_cycles"].as_u64())
            && actual > max
        {
            issues.push(format!(
                "iCKB claim branch {family_id}/{branch_id} scenario {scenario} cellscript_cycles {actual} exceeds {max}"
            ));
        }
        if let (Some(max), Some(actual)) = (max_tx_size, row["execution"]["tx_size_bytes"].as_u64())
            && actual > max
        {
            issues.push(format!("iCKB claim branch {family_id}/{branch_id} scenario {scenario} tx_size_bytes {actual} exceeds {max}"));
        }
    }
}

fn json_string_array(value: &serde_json::Value, key: &str) -> Vec<String> {
    value[key].as_array().into_iter().flatten().filter_map(serde_json::Value::as_str).map(ToString::to_string).collect()
}

fn ckb_fixture_non_empty_json_value(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null => false,
        serde_json::Value::String(value) => !value.is_empty(),
        serde_json::Value::Array(values) => !values.is_empty(),
        serde_json::Value::Object(values) => !values.is_empty(),
        serde_json::Value::Bool(_) | serde_json::Value::Number(_) => true,
    }
}

fn ckb_fixture_is_canonical_prefixed_sha256(value: &str) -> bool {
    value
        .strip_prefix("0x")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()))
}

fn validate_ckb_fixture_suite(
    suite: &serde_json::Value,
    base_dir: &Path,
    rows: &mut Vec<serde_json::Value>,
    issues: &mut Vec<String>,
) {
    let suite_name = suite["name"].as_str().unwrap_or("<unknown>");
    let accepted = ckb_fixture_names(suite, "accepted_fixtures", issues, suite_name);
    let rejected = ckb_fixture_names(suite, "rejected_fixtures", issues, suite_name);
    let Some(files) = suite["fixture_files"].as_object() else {
        issues.push(format!("suite {suite_name} missing fixture_files object"));
        return;
    };
    for fixture_name in accepted.iter().chain(rejected.iter()) {
        let Some(file) = files.get(*fixture_name).and_then(serde_json::Value::as_str) else {
            issues.push(format!("suite {suite_name} missing fixture file mapping for {fixture_name}"));
            continue;
        };
        let path = base_dir.join(file);
        let fixture = match std::fs::read_to_string(&path) {
            Ok(content) => match serde_json::from_str::<serde_json::Value>(&content) {
                Ok(value) => value,
                Err(error) => {
                    issues.push(format!("fixture {file} failed to parse: {error}"));
                    continue;
                }
            },
            Err(error) => {
                issues.push(format!("fixture {file} failed to read: {error}"));
                continue;
            }
        };
        match validate_ckb_fixture_model(&fixture, suite_name, fixture_name, accepted.contains(fixture_name), file) {
            Ok(row) => rows.push(row),
            Err(error) => issues.push(error),
        }
    }
}

fn validate_ckb_fixture_model(
    fixture: &serde_json::Value,
    suite_name: &str,
    fixture_name: &str,
    should_accept: bool,
    file: &str,
) -> std::result::Result<serde_json::Value, String> {
    if fixture["schema"].as_str() != Some(CKB_STANDARD_FIXTURE_SCHEMA) {
        return Err(format!("fixture {file} schema must be {CKB_STANDARD_FIXTURE_SCHEMA}"));
    }
    if fixture["suite"].as_str() != Some(suite_name) {
        return Err(format!("fixture {file} suite does not match manifest suite {suite_name}"));
    }
    if fixture["fixture_name"].as_str() != Some(fixture_name) {
        return Err(format!("fixture {file} fixture_name does not match manifest key {fixture_name}"));
    }

    let shape = &fixture["transaction_shape"];
    ckb_fixture_require_array(shape, "inputs")?;
    ckb_fixture_require_array(shape, "outputs")?;
    ckb_fixture_require_array(shape, "cell_deps")?;
    ckb_fixture_validate_metadata_expectation(fixture)?;
    ckb_fixture_validate_capacity_report(fixture)?;

    let expected = fixture["expected_behavior"].as_object().ok_or_else(|| format!("fixture {file} missing expected_behavior"))?;
    let expected_exit = expected
        .get("script_exit_code")
        .and_then(serde_json::Value::as_i64)
        .ok_or_else(|| format!("fixture {file} missing expected_behavior.script_exit_code"))?;
    let expected_reason = expected.get("rejection_reason").and_then(serde_json::Value::as_str);

    if should_accept && fixture["status"].as_str() != Some("accepted") {
        return Err(format!("fixture {file} is listed accepted but status is not accepted"));
    }
    if !should_accept && fixture["status"].as_str() != Some("rejected") {
        return Err(format!("fixture {file} is listed rejected but status is not rejected"));
    }
    if should_accept && expected_exit != 0 {
        return Err(format!("fixture {file} accepted case has non-zero expected exit code"));
    }
    if !should_accept && expected_exit == 0 {
        return Err(format!("fixture {file} rejected case has zero expected exit code"));
    }
    if !should_accept && expected_reason.is_none() {
        return Err(format!("fixture {file} rejected case lacks expected_behavior.rejection_reason"));
    }

    let verdict = ckb_fixture_evaluate_semantics(fixture)?;
    if verdict.0 != expected_exit {
        return Err(format!("fixture {file} model exit {} disagrees with expected exit {expected_exit}", verdict.0));
    }
    if expected_exit != 0 && verdict.1.as_deref() != expected_reason {
        return Err(format!("fixture {file} model rejection {:?} disagrees with expected {:?}", verdict.1, expected_reason));
    }

    Ok(serde_json::json!({
        "suite": suite_name,
        "fixture_name": fixture_name,
        "file": file,
        "expected_status": fixture["status"].as_str().unwrap_or("unknown"),
        "execution_level": "MODEL",
        "ckb_vm_execution": false,
        "model_exit_code": verdict.0,
        "expected_exit_code": expected_exit,
        "rejection_reason": verdict.1.or_else(|| expected_reason.map(str::to_string)),
        "status": if verdict.0 == 0 { "accepted" } else { "rejected" },
    }))
}

fn ckb_fixture_validate_metadata_expectation(fixture: &serde_json::Value) -> std::result::Result<(), String> {
    let metadata = fixture["metadata_expectation"].as_object().ok_or("fixture missing metadata_expectation")?;
    let proof_plan =
        metadata.get("proof_plan").and_then(serde_json::Value::as_object).ok_or("fixture missing proof_plan expectation")?;
    for key in ["trigger", "scope", "reads", "coverage", "on_chain_checked"] {
        if !proof_plan.contains_key(key) {
            return Err(format!("fixture proof_plan expectation missing {key}"));
        }
    }
    if !metadata.contains_key("codegen_coverage_status") {
        return Err("fixture metadata expectation missing codegen_coverage_status".to_string());
    }
    if fixture.get("cycle_report").is_none() {
        return Err("fixture missing cycle_report".to_string());
    }
    if fixture.get("capacity_report").is_none() {
        return Err("fixture missing capacity_report".to_string());
    }
    Ok(())
}

fn ckb_fixture_evaluate_semantics(fixture: &serde_json::Value) -> std::result::Result<(i64, Option<String>), String> {
    let shape = &fixture["transaction_shape"];
    match fixture["suite"].as_str().ok_or("missing suite")? {
        "sudt" => ckb_fixture_evaluate_amount_conservation(shape, "sudt-cell", "output_amount > input_amount; conservation violated"),
        "xudt" => {
            if ckb_fixture_any_cell_dep_name(shape, "lockup") || ckb_fixture_any_input_witness(shape, "lockup-active") {
                return Ok(ckb_fixture_reject("extension_policy_violated: lockup period not expired"));
            }
            ckb_fixture_evaluate_amount_conservation(shape, "xudt-cell", "output_amount > input_amount; conservation violated")
        }
        "acp" => {
            let first_input = ckb_fixture_first_cell(shape, "inputs")?;
            let first_output = ckb_fixture_first_cell(shape, "outputs")?;
            if ckb_fixture_cell_str(first_input, "witness").contains("wrong")
                || ckb_fixture_cell_str(first_input, "lock_script") != ckb_fixture_cell_str(first_output, "lock_script")
            {
                return Ok(ckb_fixture_reject("witness_lock_hash != args_owner_lock_hash"));
            }
            Ok(ckb_fixture_pass())
        }
        "cheque" => {
            let first_input = ckb_fixture_first_cell(shape, "inputs")?;
            let first_output = ckb_fixture_first_cell(shape, "outputs")?;
            if ckb_fixture_cell_str(first_input, "witness").contains("wrong")
                || ckb_fixture_cell_str(first_output, "lock_script").contains("wrong")
            {
                return Ok(ckb_fixture_reject("receiver_lock_hash != args_receiver_hash"));
            }
            Ok(ckb_fixture_pass())
        }
        "omnilock" => {
            if ckb_fixture_any_input_witness(shape, "invalid") {
                Ok(ckb_fixture_reject("auth_verification_failed: invalid_signature_or_wrong_method"))
            } else {
                Ok(ckb_fixture_pass())
            }
        }
        "nervosdao-since" => {
            if shape["header_deps"].as_array().into_iter().flatten().any(|header| header.as_str() == Some("mature-epoch-header")) {
                Ok(ckb_fixture_pass())
            } else {
                Ok(ckb_fixture_reject("since_not_mature: current_epoch < required_epoch"))
            }
        }
        "type-id" => {
            let type_id_outputs = shape["outputs"]
                .as_array()
                .ok_or("missing outputs")?
                .iter()
                .filter(|output| ckb_fixture_cell_str(output, "type_script").starts_with("type-id-script"))
                .count();
            if type_id_outputs > 1 {
                Ok(ckb_fixture_reject("duplicate_type_id: at-most-one-input-and-one-output-per-type-id-group"))
            } else {
                Ok(ckb_fixture_pass())
            }
        }
        other => Err(format!("unsupported compat fixture suite {other}")),
    }
}

fn ckb_fixture_evaluate_amount_conservation(
    shape: &serde_json::Value,
    cell_type: &str,
    reason: &str,
) -> std::result::Result<(i64, Option<String>), String> {
    let input_sum = ckb_fixture_amount_sum(shape, "inputs", cell_type)?;
    let output_sum = ckb_fixture_amount_sum(shape, "outputs", cell_type)?;
    if output_sum > input_sum {
        Ok(ckb_fixture_reject(reason))
    } else {
        Ok(ckb_fixture_pass())
    }
}

fn ckb_fixture_amount_sum(shape: &serde_json::Value, side: &str, cell_type: &str) -> std::result::Result<u128, String> {
    shape[side]
        .as_array()
        .ok_or_else(|| format!("missing transaction_shape.{side}"))?
        .iter()
        .filter(|cell| ckb_fixture_cell_str(cell, "type") == cell_type)
        .try_fold(0u128, |total, cell| Ok(total + ckb_fixture_little_endian_u128(ckb_fixture_cell_str(cell, "data"))?))
}

fn ckb_fixture_little_endian_u128(hex_value: &str) -> std::result::Result<u128, String> {
    let bytes = hex_value.strip_prefix("0x").unwrap_or(hex_value);
    if bytes.is_empty() {
        return Ok(0);
    }
    if !bytes.len().is_multiple_of(2) {
        return Err(format!("odd-length hex amount {hex_value}"));
    }
    let raw = hex::decode(bytes).map_err(|err| format!("invalid hex amount {hex_value}: {err}"))?;
    if raw.len() > 16 {
        return Err(format!("amount data exceeds u128 width: {} bytes", raw.len()));
    }
    let mut padded = [0u8; 16];
    padded[..raw.len()].copy_from_slice(&raw);
    Ok(u128::from_le_bytes(padded))
}

fn ckb_fixture_validate_capacity_report(fixture: &serde_json::Value) -> std::result::Result<(), String> {
    let reported = fixture["capacity_report"]["occupied_capacity_shannons"]
        .as_u64()
        .ok_or("capacity_report missing occupied_capacity_shannons")?;
    let output_capacity = fixture["transaction_shape"]["outputs"]
        .as_array()
        .ok_or("missing outputs")?
        .iter()
        .map(|output| output["capacity_shannons"].as_u64().ok_or("output missing capacity_shannons"))
        .try_fold(0u64, |total, value| value.map(|value| total.saturating_add(value)))?;
    if reported > output_capacity {
        return Err(format!("capacity report occupied capacity {reported} exceeds output capacity {output_capacity}"));
    }
    Ok(())
}

fn ckb_fixture_names<'a>(suite: &'a serde_json::Value, key: &str, issues: &mut Vec<String>, suite_name: &str) -> BTreeSet<&'a str> {
    match suite[key].as_array() {
        Some(values) => values.iter().filter_map(serde_json::Value::as_str).collect(),
        None => {
            issues.push(format!("suite {suite_name} missing {key} array"));
            BTreeSet::new()
        }
    }
}

fn ckb_fixture_require_array(value: &serde_json::Value, key: &str) -> std::result::Result<(), String> {
    value[key].as_array().map(|_| ()).ok_or_else(|| format!("missing transaction_shape.{key}"))
}

fn ckb_fixture_first_cell<'a>(shape: &'a serde_json::Value, side: &str) -> std::result::Result<&'a serde_json::Value, String> {
    shape[side].as_array().and_then(|cells| cells.first()).ok_or_else(|| format!("missing first transaction_shape.{side} cell"))
}

fn ckb_fixture_cell_str<'a>(cell: &'a serde_json::Value, field: &str) -> &'a str {
    cell[field].as_str().unwrap_or("")
}

fn ckb_fixture_any_cell_dep_name(shape: &serde_json::Value, needle: &str) -> bool {
    shape["cell_deps"].as_array().into_iter().flatten().any(|dep| dep["name"].as_str().is_some_and(|name| name.contains(needle)))
}

fn ckb_fixture_any_input_witness(shape: &serde_json::Value, needle: &str) -> bool {
    shape["inputs"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|input| input["witness"].as_str().is_some_and(|witness| witness.contains(needle)))
}

fn ckb_fixture_pass() -> (i64, Option<String>) {
    (0, None)
}

fn ckb_fixture_reject(reason: &str) -> (i64, Option<String>) {
    (1, Some(reason.to_string()))
}

fn transaction_solver_template(metadata: &CompileMetadata) -> serde_json::Value {
    let assumptions = &metadata.runtime.builder_assumptions;
    let ckb = metadata.constraints.ckb.as_ref();

    // Cell selection: derive input requirements from actions and ProofPlan
    let mut input_slots = Vec::new();
    let mut output_slots = Vec::new();
    let mut dep_slots = Vec::new();
    let mut witness_slots = Vec::new();

    // Build input slots from consume/consume_set patterns in actions
    for action in &metadata.actions {
        for plan in &action.proof_plan {
            if plan.reads.iter().any(|r| r == "input" || r == "group_input") {
                input_slots.push(serde_json::json!({
                    "source": "proof-plan-input",
                    "scope_kind": "action",
                    "scope_name": action.name,
                    "feature": plan.feature,
                    "required_reads": plan.reads.iter().filter(|r| **r == "input" || **r == "group_input").cloned().collect::<Vec<_>>(),
                }));
            }
        }
    }

    // Build output slots from create/create_set patterns
    for action in &metadata.actions {
        for plan in &action.proof_plan {
            if plan.reads.iter().any(|r| r == "output" || r == "group_output") {
                output_slots.push(serde_json::json!({
                    "source": "proof-plan-output",
                    "scope_kind": "action",
                    "scope_name": action.name,
                    "feature": plan.feature,
                    "required_reads": plan.reads.iter().filter(|r| **r == "output" || **r == "group_output").cloned().collect::<Vec<_>>(),
                }));
            }
        }
    }

    // Build lock input/output slots
    for lock in &metadata.locks {
        for plan in &lock.proof_plan {
            if plan.reads.iter().any(|r| r == "input" || r == "group_input") {
                input_slots.push(serde_json::json!({
                    "source": "proof-plan-input",
                    "scope_kind": "lock",
                    "scope_name": lock.name,
                    "feature": plan.feature,
                    "required_reads": plan.reads.iter().filter(|r| **r == "input" || **r == "group_input").cloned().collect::<Vec<_>>(),
                }));
            }
            if plan.reads.iter().any(|r| r == "output" || r == "group_output") {
                output_slots.push(serde_json::json!({
                    "source": "proof-plan-output",
                    "scope_kind": "lock",
                    "scope_name": lock.name,
                    "feature": plan.feature,
                    "required_reads": plan.reads.iter().filter(|r| **r == "output" || **r == "group_output").cloned().collect::<Vec<_>>(),
                }));
            }
        }
    }

    // Dep resolution from CKB constraints
    if let Some(ckb_constraints) = ckb {
        for dep in &ckb_constraints.dep_group_manifest.declared_cell_deps {
            dep_slots.push(serde_json::json!({
                "source": "metadata-script-reference",
                "name": dep.name,
                "dep_type": dep.dep_type,
                "hash_type": dep.hash_type,
            }));
        }
        for script_ref in &ckb_constraints.script_references {
            dep_slots.push(serde_json::json!({
                "source": "metadata-script-reference",
                "name": script_ref.name,
                "scope": script_ref.scope,
                "purpose": script_ref.purpose,
            }));
        }
    }

    // Witness placement from builder assumptions
    let witness_fields = assumptions
        .iter()
        .flat_map(|assumption| assumption.required_witness_fields.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if !witness_fields.is_empty() {
        witness_slots.push(serde_json::json!({
            "source": "builder-assumption-witness-fields",
            "fields": witness_fields,
        }));
    }

    // Evidence requirements
    let evidence = assumptions
        .iter()
        .filter(|assumption| {
            matches!(
                assumption.kind.as_str(),
                "create_unique_global_uniqueness"
                    | "type_id_builder_plan"
                    | "metadata_only_gap"
                    | "runtime_required_proof_plan"
                    | "lock_group_transaction_scope"
                    | "capacity_policy"
            )
        })
        .map(|assumption| {
            serde_json::json!({
                "assumption_id": assumption.assumption_id,
                "kind": assumption.kind,
                "origin": assumption.origin,
                "feature": assumption.feature,
                "proof_plan_status": assumption.proof_plan_status,
                "detail": assumption.detail,
                "evidence_schema": evidence_schema_for_assumption(assumption),
            })
        })
        .collect::<Vec<_>>();

    // Fee/change planning from CKB constraints
    let fee_planning = ckb
        .map(|c| {
            serde_json::json!({
                "capacity_planning_required": c.capacity_planning_required,
                "capacity_policy": c.capacity_policy_surface,
                "created_output_count": c.created_output_count,
                "mutated_output_count": c.mutated_output_count,
                "occupied_capacity_evidence": c.capacity_evidence_contract.measured_occupied_capacity_shannons,
                "tx_size_bytes": c.tx_size_bytes,
            })
        })
        .unwrap_or(serde_json::json!(null));

    // Deterministic signing manifest
    let signature_requests = metadata
        .locks
        .iter()
        .map(|lock| {
            serde_json::json!({
                "lock_name": lock.name,
                "witness_index": format!("lock:{}:witness_0", lock.name),
                "signature_policy": "explicit-witness-no-implicit-signer",
            })
        })
        .collect::<Vec<_>>();

    let header_dep_slots = ckb
        .map(|c| {
            if c.uses_header_epoch {
                vec![serde_json::json!({
                    "source": "metadata-requirement",
                    "kind": "header_dep",
                    "status": "unresolved",
                    "required_external_step": "resolve concrete epoch/header dep before transaction construction",
                })]
            } else {
                Vec::new()
            }
        })
        .unwrap_or_default();

    serde_json::json!({
        "status": "template-only",
        "solver": "cellscript-v0.16-transaction-template-emitter",
        "solver_capability": "template-emitter-only",
        "solver_readiness": "not-a-solver",
        "execution_mode": "non-executable-template",
        "can_submit": false,
        "requires_validate_tx": true,
        "module": metadata.module,
        "target_profile": metadata.target_profile.name,
        "transaction_plan": {
            "version": 0,
            "inputs": input_slots,
            "outputs": output_slots,
            "cell_deps": dep_slots,
            "witnesses": witness_slots,
            "header_deps": header_dep_slots,
            "header_deps_status": "unresolved-template-slots",
            "builder_assumption_evidence_requirements": evidence,
        },
        "fee_change_plan": fee_planning,
        "signing_manifest": {
            "policy": "explicit-witness-no-implicit-signer",
            "signature_requests": signature_requests,
        },
        "builder_assumptions": assumptions,
        "required_external_steps": [
            "live cell selection",
            "concrete CellDep and HeaderDep resolution",
            "fee and change calculation",
            "occupied-capacity and under-capacity measurement",
            "witness placement and signing",
            "CKB dry-run or VM verification"
        ],
        "limitations": [
            "template only: does not perform live cell selection",
            "template only: does not resolve concrete deps/header deps",
            "template only: does not calculate fee/change or occupied capacity",
            "template only: does not place final witnesses or signatures",
            "CKB dry-run required for production acceptance"
        ],
    })
}

fn evidence_schema_for_assumption(assumption: &crate::BuilderAssumptionMetadata) -> serde_json::Value {
    let mut payload_arrays = Vec::new();
    if !assumption.required_inputs.is_empty() {
        payload_arrays.push(serde_json::json!({
            "name": "inputs",
            "aliases": ["input_cells", "required_inputs"],
            "transaction_array": "inputs",
            "item_required_fields": ["index"],
            "item_concrete_fields": ["source", "out_point", "type_hash", "lock_hash", "capacity"],
        }));
    }
    if !assumption.required_outputs.is_empty() {
        payload_arrays.push(serde_json::json!({
            "name": "outputs",
            "aliases": ["output_cells", "required_outputs"],
            "transaction_array": "outputs",
            "item_required_fields": ["index"],
            "item_concrete_fields": ["source", "type_hash", "lock_hash", "capacity", "data"],
        }));
    }
    if !assumption.required_cell_deps.is_empty() {
        payload_arrays.push(serde_json::json!({
            "name": "cell_deps",
            "aliases": ["required_cell_deps"],
            "transaction_array": "cell_deps",
            "item_required_fields": ["index"],
            "item_concrete_fields": ["name", "out_point", "code_hash", "tx_hash", "dep_type"],
        }));
    }
    if !assumption.required_witness_fields.is_empty() {
        payload_arrays.push(serde_json::json!({
            "name": "witnesses",
            "aliases": ["witness_fields", "required_witness_fields"],
            "transaction_array": "witnesses",
            "item_required_fields": ["index", "field"],
            "item_concrete_fields": ["field", "lock", "input_type", "output_type", "bytes"],
        }));
    }

    let mut payload_objects = Vec::new();
    if assumption.kind == "capacity_policy" || assumption.capacity_policy != "none" {
        payload_objects.push(serde_json::json!({
            "name": "capacity",
            "required_fields": ["occupied_capacity_shannons", "tx_size_bytes", "under_capacity_output_indexes"],
            "failure_rule": "under_capacity_output_indexes must be an empty array for tx validate success",
        }));
    }
    if assumption.kind == "type_id_builder_plan" {
        payload_objects.push(serde_json::json!({
            "name": "type_id",
            "required_fields": ["first_input_out_point", "output_index", "expected_type_id_args"],
            "expected_type_id_args": "canonical 0x-prefixed 32-byte hex",
            "transaction_cross_check": "output_index must point to the output whose type args equal expected_type_id_args when the tx JSON exposes type args",
        }));
    }
    if assumption.kind == "create_unique_global_uniqueness" {
        payload_objects.push(serde_json::json!({
            "name": "uniqueness",
            "required_any_of": ["uniqueness_checked=true", "uniqueness_proof", "unique_cell"],
        }));
    }
    if assumption.kind == "lock_group_transaction_scope" {
        payload_objects.push(serde_json::json!({
            "name": "lock_group_transaction_scope",
            "required_any_of": ["transaction_scope_reviewed=true", "covered_lock_groups"],
        }));
    }
    if matches!(assumption.kind.as_str(), "metadata_only_gap" | "runtime_required_proof_plan") {
        payload_objects.push(serde_json::json!({
            "name": "manual_review",
            "required_any_of": ["manual_review", "checked=true"],
        }));
    }

    serde_json::json!({
        "required_fields": ["assumption_id", "kind", "origin", "feature", "proof_plan_status", "evidence"],
        "payload_type": "object",
        "payload_arrays": payload_arrays,
        "payload_objects": payload_objects,
        "cross_checks": [
            "array evidence items must include numeric index fields that bind to the transaction array",
            "when evidence and the indexed transaction object both expose a concrete field, tx validate requires equality",
            "capacity evidence must fail closed when under-capacity outputs are reported",
            "TYPE_ID evidence must use canonical 32-byte args and match output type args when present"
        ],
        "note": "builder must replace this requirement with concrete evidence before tx validate can pass",
    })
}

fn deployment_plan_json(metadata: &CompileMetadata) -> serde_json::Value {
    let ckb = metadata.constraints.ckb.as_ref();
    serde_json::json!({
        "status": "ok",
        "schema": "cellscript-deploy-plan-v0.16",
        "module": metadata.module,
        "compiler_version": metadata.compiler_version,
        "metadata_schema_version": metadata.metadata_schema_version,
        "metadata_schema_versions": metadata_schema_versions_json(metadata),
        "artifact": {
            "format": metadata.artifact_format,
            "hash": metadata.artifact_hash,
            "size_bytes": metadata.artifact_size_bytes,
        },
        "target_profile": metadata.target_profile,
        "code_cell_manifest": {
            "hash_type": ckb.map(|c| c.declared_type_id_hash_type.as_str()).unwrap_or("type"),
            "capacity_policy": ckb.map(|c| c.capacity_policy_surface.as_str()).unwrap_or("unknown"),
        },
        "dep_group_manifest": ckb.map(|c| serde_json::to_value(&c.dep_group_manifest).unwrap_or(serde_json::Value::Null)),
        "script_references": ckb.map(|c| serde_json::to_value(&c.script_references).unwrap_or(serde_json::Value::Null)),
        "proof_plan_soundness": metadata.runtime.proof_plan_soundness,
        "builder_assumptions": metadata.runtime.builder_assumptions,
    })
}

fn verify_deploy_plan_json(plan: &serde_json::Value) -> Vec<String> {
    let mut violations = Vec::new();
    if plan.get("schema").and_then(serde_json::Value::as_str) != Some("cellscript-deploy-plan-v0.16") {
        violations.push("schema must be cellscript-deploy-plan-v0.16".to_string());
    }
    if plan.pointer("/artifact/format").is_none() {
        violations.push("artifact.format is required".to_string());
    }
    match plan.pointer("/artifact/hash").and_then(serde_json::Value::as_str) {
        Some(hash) if hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) => {}
        Some(_) => violations.push("artifact.hash must be a canonical 32-byte lowercase hex hash".to_string()),
        None => violations.push("artifact.hash is required".to_string()),
    }
    match plan.pointer("/artifact/size_bytes").and_then(serde_json::Value::as_u64) {
        Some(size) if size > 0 => {}
        Some(_) => violations.push("artifact.size_bytes must be greater than zero".to_string()),
        None => violations.push("artifact.size_bytes is required".to_string()),
    }
    match plan.get("metadata_schema_version").and_then(serde_json::Value::as_u64) {
        Some(version) if version > 0 => {}
        Some(_) => violations.push("metadata_schema_version must be greater than zero".to_string()),
        None => violations.push("metadata_schema_version is required".to_string()),
    }
    for field in ["metadata", "source", "artifact", "constraints"] {
        match plan.pointer(&format!("/metadata_schema_versions/{field}")).and_then(serde_json::Value::as_u64) {
            Some(version) if version > 0 => {}
            Some(_) => violations.push(format!("metadata_schema_versions.{field} must be greater than zero")),
            None => violations.push(format!("metadata_schema_versions.{field} is required")),
        }
    }
    if plan.get("target_profile").is_none() {
        violations.push("target_profile is required".to_string());
    }
    match plan.pointer("/proof_plan_soundness/status").and_then(serde_json::Value::as_str) {
        Some("passed") => {}
        Some(status) => violations.push(format!("proof_plan_soundness.status must be passed, got {status}")),
        None => violations.push("proof_plan_soundness.status is required".to_string()),
    }
    if plan.get("builder_assumptions").is_none() {
        violations.push("builder_assumptions is required".to_string());
    }
    violations
}

fn dependency_lock_json(metadata: &CompileMetadata) -> serde_json::Value {
    let ckb = metadata.constraints.ckb.as_ref();
    serde_json::json!({
        "status": "ok",
        "schema": "cellscript-dependency-lock-v0.16",
        "module": metadata.module,
        "metadata_schema_version": metadata.metadata_schema_version,
        "metadata_schema_versions": metadata_schema_versions_json(metadata),
        "artifact_hash": metadata.artifact_hash,
        "cell_deps": ckb.map(|c| serde_json::to_value(&c.dep_group_manifest.declared_cell_deps).unwrap_or(serde_json::Value::Null)),
        "script_references": ckb.map(|c| serde_json::to_value(&c.script_references).unwrap_or(serde_json::Value::Null)),
    })
}

fn proof_diff_report(old: &CompileMetadata, new: &CompileMetadata) -> serde_json::Value {
    let old_map = proof_plan_map(&old.runtime.proof_plan);
    let new_map = proof_plan_map(&new.runtime.proof_plan);
    let old_keys = old_map.keys().cloned().collect::<BTreeSet<_>>();
    let new_keys = new_map.keys().cloned().collect::<BTreeSet<_>>();
    let added = new_keys.difference(&old_keys).cloned().collect::<Vec<_>>();
    let removed = old_keys.difference(&new_keys).cloned().collect::<Vec<_>>();
    let changed = old_keys.intersection(&new_keys).filter(|key| old_map.get(*key) != new_map.get(*key)).cloned().collect::<Vec<_>>();
    serde_json::json!({
        "status": "ok",
        "schema": "cellscript-proof-diff-v0.16",
        "old_module": old.module,
        "new_module": new.module,
        "added": added,
        "removed": removed,
        "changed": changed,
    })
}

fn proof_plan_map(plans: &[ProofPlanMetadata]) -> BTreeMap<String, serde_json::Value> {
    plans
        .iter()
        .map(|plan| {
            (
                format!("{}:{}:{}", plan.origin, plan.feature, plan.status),
                serde_json::json!({
                    "trigger": plan.trigger,
                    "scope": plan.scope,
                    "reads": plan.reads,
                    "coverage": plan.coverage,
                    "codegen_coverage_status": plan.codegen_coverage_status,
                    "on_chain_checked": plan.on_chain_checked,
                }),
            )
        })
        .collect()
}

fn json_diff_report(kind: &str, old: &serde_json::Value, new: &serde_json::Value) -> serde_json::Value {
    let changed = [
        "/artifact/hash",
        "/artifact/size_bytes",
        "/target_profile/name",
        "/proof_plan_soundness/status",
        "/metadata_schema_version",
        "/metadata_schema_versions/metadata",
        "/metadata_schema_versions/source",
        "/metadata_schema_versions/artifact",
        "/metadata_schema_versions/constraints",
    ]
    .iter()
    .filter(|pointer| old.pointer(pointer) != new.pointer(pointer))
    .map(|pointer| {
        serde_json::json!({
            "path": pointer,
            "old": old.pointer(pointer).cloned().unwrap_or(serde_json::Value::Null),
            "new": new.pointer(pointer).cloned().unwrap_or(serde_json::Value::Null),
        })
    })
    .collect::<Vec<_>>();
    serde_json::json!({
        "status": "ok",
        "schema": format!("cellscript-{}-diff-v0.16", kind),
        "changed": changed,
    })
}

fn profile_report_json(metadata: &CompileMetadata, entry: Option<&str>) -> serde_json::Value {
    let mut proof_plan_records = Vec::new();
    let actions = metadata
        .actions
        .iter()
        .filter(|action| entry.is_none_or(|entry| action.name == entry))
        .map(|action| {
            proof_plan_records.extend(action.proof_plan.iter().map(|plan| {
                profile_proof_plan_record_json(
                    "action",
                    &action.name,
                    serde_json::json!(action.estimated_cycles),
                    action.ckb_runtime_accesses.len(),
                    plan,
                )
            }));
            serde_json::json!({
                "kind": "action",
                "name": action.name,
                "estimated_cycles": action.estimated_cycles,
                "proof_plan_records": action.proof_plan.len(),
                "runtime_accesses": action.ckb_runtime_accesses.len(),
            })
        })
        .collect::<Vec<_>>();
    let locks = metadata
        .locks
        .iter()
        .filter(|lock| entry.is_none_or(|entry| lock.name == entry))
        .map(|lock| {
            proof_plan_records.extend(lock.proof_plan.iter().map(|plan| {
                profile_proof_plan_record_json("lock", &lock.name, serde_json::Value::Null, lock.ckb_runtime_accesses.len(), plan)
            }));
            serde_json::json!({
                "kind": "lock",
                "name": lock.name,
                "estimated_cycles": null,
                "proof_plan_records": lock.proof_plan.len(),
                "runtime_accesses": lock.ckb_runtime_accesses.len(),
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "status": "ok",
        "schema": "cellscript-profile-v0.16",
        "module": metadata.module,
        "entry": entry,
        "actions": actions,
        "locks": locks,
        "proof_plan_records": proof_plan_records,
        "proof_plan_soundness": metadata.runtime.proof_plan_soundness,
    })
}

fn profile_proof_plan_record_json(
    entry_kind: &str,
    entry_name: &str,
    estimated_cycles: serde_json::Value,
    runtime_accesses: usize,
    plan: &ProofPlanMetadata,
) -> serde_json::Value {
    serde_json::json!({
        "entry_kind": entry_kind,
        "entry_name": entry_name,
        "name": plan.name,
        "origin": plan.origin,
        "category": plan.category,
        "feature": plan.feature,
        "trigger": plan.trigger,
        "scope": plan.scope,
        "reads": plan.reads,
        "coverage": plan.coverage,
        "codegen_coverage_status": plan.codegen_coverage_status,
        "on_chain_checked": plan.on_chain_checked,
        "status": plan.status,
        "estimated_cycles": estimated_cycles,
        "runtime_accesses": runtime_accesses,
        "builder_assumptions": plan.builder_assumptions,
        "detail": plan.detail,
    })
}

fn trace_tx_report_json(metadata: &CompileMetadata, validation: &crate::TxValidationReport) -> serde_json::Value {
    serde_json::json!({
        "status": validation.status,
        "schema": "cellscript-tx-trace-v0.16",
        "module": metadata.module,
        "steps": metadata.runtime.builder_assumptions.iter().map(|assumption| {
            serde_json::json!({
                "assumption_id": assumption.assumption_id,
                "kind": assumption.kind,
                "origin": assumption.origin,
                "feature": assumption.feature,
                "checked": validation.checked_assumptions.contains(&assumption.assumption_id),
            })
        }).collect::<Vec<_>>(),
        "validation": validation,
    })
}

fn protocol_graph_json(metadata: &CompileMetadata) -> serde_json::Value {
    let mut vertices = BTreeMap::<String, serde_json::Value>::new();
    let type_names = metadata.types.iter().map(|ty| ty.name.clone()).collect::<BTreeSet<_>>();

    for ty in &metadata.types {
        if ty.flow_states.is_empty() {
            protocol_graph_insert_vertex(
                &mut vertices,
                protocol_graph_type_vertex_id(&ty.name),
                &ty.name,
                &ty.kind,
                Some(&ty.name),
                None,
                false,
                false,
                false,
            );
        } else {
            for state in &ty.flow_states {
                protocol_graph_insert_vertex(
                    &mut vertices,
                    protocol_graph_state_vertex_id(&ty.name, state),
                    &format!("{}[{}]", ty.name, state),
                    &ty.kind,
                    Some(&ty.name),
                    Some(state),
                    false,
                    ty.flow_initial_state.as_deref() == Some(state.as_str()),
                    ty.flow_terminal_states.iter().any(|terminal| terminal == state),
                );
            }
        }
    }

    let mut edges = Vec::new();
    let mut seen_edges = BTreeSet::new();
    for action in &metadata.actions {
        for edge in &action.state_transition_edges {
            let source = protocol_graph_state_vertex_id(&edge.type_name, &edge.from);
            let target = protocol_graph_state_vertex_id(&edge.type_name, &edge.to);
            protocol_graph_push_edge(
                &mut edges,
                &mut seen_edges,
                action,
                source,
                target,
                "state-transition",
                Some(serde_json::json!({
                    "type_name": &edge.type_name,
                    "field_name": &edge.field_name,
                    "from": &edge.from,
                    "to": &edge.to,
                    "from_index": edge.from_index,
                    "to_index": edge.to_index,
                    "input_binding": &edge.input_binding,
                    "output_binding": &edge.output_binding,
                })),
            );
        }

        if action.state_transition_edges.is_empty() {
            let (sources, targets) = protocol_graph_type_pattern_vertices(action, &type_names);
            for source in sources {
                protocol_graph_ensure_vertex(&mut vertices, &source);
                for target in &targets {
                    protocol_graph_ensure_vertex(&mut vertices, target);
                    protocol_graph_push_edge(
                        &mut edges,
                        &mut seen_edges,
                        action,
                        source.clone(),
                        target.clone(),
                        "type-pattern",
                        None,
                    );
                }
            }
        }
    }

    let vertex_values = vertices.values().cloned().collect::<Vec<_>>();
    let cycle_detected = protocol_graph_has_cycle(&edges);
    let self_loop_count = edges.iter().filter(|edge| edge.get("source_vertex") == edge.get("target_vertex")).count();
    let role_lints = protocol_graph_role_lints(&edges);

    serde_json::json!({
        "status": "ok",
        "schema": "cellscript-protocol-graph-v0.22",
        "derivation": "derived-from-compile-metadata",
        "consensus_checked": false,
        "module": metadata.module,
        "target_profile": metadata.target_profile.name,
        "vertex_count": vertex_values.len(),
        "edge_count": edges.len(),
        "cycle_detected": cycle_detected,
        "self_loop_count": self_loop_count,
        "role_model": {
            "semantics": "explanatory-metadata-only",
            "evidence_tier": "metadata-only",
            "authorization_proven": false,
            "source_precedence": ["verification-predicate", "witness-or-lock-args-binding", "field-name"],
        },
        "role_warning_count": role_lints.len(),
        "role_lints": role_lints,
        "vertices": vertex_values,
        "edges": edges,
    })
}

fn protocol_graph_insert_vertex(
    vertices: &mut BTreeMap<String, serde_json::Value>,
    id: String,
    label: &str,
    kind: &str,
    type_name: Option<&str>,
    state: Option<&str>,
    synthetic: bool,
    initial: bool,
    terminal: bool,
) {
    vertices.entry(id.clone()).or_insert_with(|| {
        serde_json::json!({
            "id": id,
            "label": label,
            "kind": kind,
            "type_name": type_name,
            "state": state,
            "synthetic": synthetic,
            "initial": initial,
            "terminal": terminal,
        })
    });
}

fn protocol_graph_ensure_vertex(vertices: &mut BTreeMap<String, serde_json::Value>, id: &str) {
    if vertices.contains_key(id) {
        return;
    }
    let (label, kind) = match id {
        "transaction:start" => ("transaction start", "transaction-boundary"),
        "transaction:end" => ("transaction end", "transaction-boundary"),
        other => (other, "type"),
    };
    protocol_graph_insert_vertex(vertices, id.to_string(), label, kind, None, None, true, false, false);
}

fn protocol_graph_push_edge(
    edges: &mut Vec<serde_json::Value>,
    seen: &mut BTreeSet<(String, String, String, String)>,
    action: &crate::ActionMetadata,
    source: String,
    target: String,
    derivation: &str,
    state_transition: Option<serde_json::Value>,
) {
    let key = (action.name.clone(), source.clone(), target.clone(), derivation.to_string());
    if !seen.insert(key) {
        return;
    }
    let proof_plan_ids = action.proof_plan.iter().map(|plan| format!("{}:{}", plan.origin, plan.feature)).collect::<Vec<_>>();
    let builder_assumptions = action
        .proof_plan
        .iter()
        .flat_map(|plan| plan.builder_assumptions.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let source_span = action.proof_plan.iter().find_map(|plan| plan.source_span.clone());
    let role = protocol_graph_role_view(action);

    edges.push(serde_json::json!({
        "action_name": &action.name,
        "source_vertex": source,
        "target_vertex": target,
        "derivation": derivation,
        "state_transition": state_transition,
        "consume_set": &action.consume_set,
        "read_refs": &action.read_refs,
        "create_set": &action.create_set,
        "mutate_set": &action.mutate_set,
        "proof_plan_ids": proof_plan_ids,
        "ckb_runtime_accesses": &action.ckb_runtime_accesses,
        "builder_assumptions": builder_assumptions,
        "touches_shared": &action.touches_shared,
        "source_span": source_span,
        "role": role["role"].clone(),
        "role_source": role["role_source"].clone(),
        "role_strength": role["role_strength"].clone(),
        "role_status": role["role_status"].clone(),
        "role_source_used": role["role_source_used"].clone(),
        "role_candidates": role["role_candidates"].clone(),
        "role_conflict": role["role_conflict"].clone(),
        "role_warnings": role["role_warnings"].clone(),
        "role_evidence_tier": "metadata-only",
        "authorization_proven": false,
    }));
}

fn protocol_graph_role_view(action: &crate::ActionMetadata) -> serde_json::Value {
    let selected = action.protocol_role_candidates.first();
    let roles = action.protocol_role_candidates.iter().map(|candidate| candidate.role.as_str()).collect::<BTreeSet<_>>();
    let conflict = roles.len() > 1;
    let mut warnings = Vec::new();

    if selected.is_none() {
        warnings.push(serde_json::json!({
            "code": "PG-ROLE-MISSING",
            "severity": "warning",
            "action_name": &action.name,
            "message": format!(
                "action '{}' has no explicit predicate, witness/lock_args binding, or weak participant field candidate; role remains unknown",
                action.name
            ),
        }));
    }
    if selected.is_some_and(|candidate| candidate.source == "field-name") {
        warnings.push(serde_json::json!({
            "code": "PG-ROLE-WEAK-FIELD",
            "severity": "warning",
            "action_name": &action.name,
            "message": format!(
                "action '{}' role '{}' comes only from a field name and does not prove signer or authorization authority",
                action.name,
                selected.map_or("unknown", |candidate| candidate.role.as_str())
            ),
        }));
    }
    if conflict {
        let sources = action
            .protocol_role_candidates
            .iter()
            .map(|candidate| format!("{}@{}", candidate.role, candidate.source))
            .collect::<Vec<_>>();
        warnings.push(serde_json::json!({
            "code": "PG-ROLE-CONFLICT",
            "severity": "warning",
            "action_name": &action.name,
            "message": format!(
                "action '{}' has conflicting role candidates [{}]; selected '{}@{}' by canonical source precedence",
                action.name,
                sources.join(", "),
                selected.map_or("unknown", |candidate| candidate.role.as_str()),
                selected.map_or("none", |candidate| candidate.source.as_str())
            ),
        }));
    }

    let status = if selected.is_none() {
        "missing"
    } else if conflict {
        "conflicting"
    } else if selected.is_some_and(|candidate| candidate.source == "field-name") {
        "weak-field-inference"
    } else {
        "attributed"
    };

    serde_json::json!({
        "role": selected.map(|candidate| candidate.role.as_str()),
        "role_source": selected.map(|candidate| candidate.source.as_str()),
        "role_strength": selected.map(|candidate| candidate.strength.as_str()),
        "role_status": status,
        "role_source_used": selected,
        "role_candidates": &action.protocol_role_candidates,
        "role_conflict": conflict,
        "role_warnings": warnings,
    })
}

fn protocol_graph_role_lints(edges: &[serde_json::Value]) -> Vec<serde_json::Value> {
    let mut lints = BTreeMap::new();
    for edge in edges {
        let Some(warnings) = edge.get("role_warnings").and_then(serde_json::Value::as_array) else {
            continue;
        };
        for warning in warnings {
            let action = warning.get("action_name").and_then(serde_json::Value::as_str).unwrap_or_default();
            let code = warning.get("code").and_then(serde_json::Value::as_str).unwrap_or_default();
            let message = warning.get("message").and_then(serde_json::Value::as_str).unwrap_or_default();
            lints.entry(format!("{action}\0{code}\0{message}")).or_insert_with(|| warning.clone());
        }
    }
    lints.into_values().collect()
}

fn protocol_graph_type_pattern_vertices(action: &crate::ActionMetadata, type_names: &BTreeSet<String>) -> (Vec<String>, Vec<String>) {
    let param_types = action
        .params
        .iter()
        .filter_map(|param| protocol_graph_base_type(&param.ty, type_names).map(|ty| (param.name.as_str(), ty)))
        .collect::<BTreeMap<_, _>>();
    let mut sources = BTreeSet::new();
    let mut targets = BTreeSet::new();

    for pattern in &action.consume_set {
        if let Some(ty) = param_types.get(pattern.binding.as_str()) {
            sources.insert(protocol_graph_type_vertex_id(ty));
        }
    }
    for pattern in &action.mutate_set {
        sources.insert(protocol_graph_type_vertex_id(&pattern.ty));
        targets.insert(protocol_graph_type_vertex_id(&pattern.ty));
    }
    for pattern in &action.create_set {
        targets.insert(protocol_graph_type_vertex_id(&pattern.ty));
    }

    if sources.is_empty() {
        sources.insert("transaction:start".to_string());
    }
    if targets.is_empty() {
        targets.insert("transaction:end".to_string());
    }

    (sources.into_iter().collect(), targets.into_iter().collect())
}

fn protocol_graph_base_type(ty: &str, type_names: &BTreeSet<String>) -> Option<String> {
    let trimmed = ty.trim().trim_start_matches('&').trim();
    let trimmed = trimmed.strip_prefix("mut ").unwrap_or(trimmed).trim();
    let base = trimmed.split('<').next().unwrap_or(trimmed).trim();
    type_names.contains(base).then(|| base.to_string())
}

fn protocol_graph_type_vertex_id(type_name: &str) -> String {
    type_name.to_string()
}

fn protocol_graph_state_vertex_id(type_name: &str, state: &str) -> String {
    format!("{}:{}", type_name, state)
}

fn protocol_graph_has_cycle(edges: &[serde_json::Value]) -> bool {
    let mut adjacency = BTreeMap::<String, Vec<String>>::new();
    for edge in edges {
        let Some(source) = edge.get("source_vertex").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let Some(target) = edge.get("target_vertex").and_then(serde_json::Value::as_str) else {
            continue;
        };
        adjacency.entry(source.to_string()).or_default().push(target.to_string());
    }

    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    for node in adjacency.keys() {
        if protocol_graph_cycle_visit(node, &adjacency, &mut visiting, &mut visited) {
            return true;
        }
    }
    false
}

fn protocol_graph_cycle_visit(
    node: &str,
    adjacency: &BTreeMap<String, Vec<String>>,
    visiting: &mut BTreeSet<String>,
    visited: &mut BTreeSet<String>,
) -> bool {
    if visited.contains(node) {
        return false;
    }
    if !visiting.insert(node.to_string()) {
        return true;
    }
    if let Some(targets) = adjacency.get(node) {
        for target in targets {
            if protocol_graph_cycle_visit(target, adjacency, visiting, visited) {
                return true;
            }
        }
    }
    visiting.remove(node);
    visited.insert(node.to_string());
    false
}

fn protocol_graph_mermaid(graph: &serde_json::Value) -> String {
    let mut output = String::from("flowchart LR\n");
    let mut ids = BTreeMap::new();
    if let Some(vertices) = graph.get("vertices").and_then(serde_json::Value::as_array) {
        for (index, vertex) in vertices.iter().enumerate() {
            let id = vertex.get("id").and_then(serde_json::Value::as_str).unwrap_or("vertex");
            let label = vertex.get("label").and_then(serde_json::Value::as_str).unwrap_or(id);
            let mermaid_id = format!("v{}", index);
            ids.insert(id.to_string(), mermaid_id.clone());
            let initial = vertex.get("initial").and_then(serde_json::Value::as_bool).unwrap_or(false);
            let terminal = vertex.get("terminal").and_then(serde_json::Value::as_bool).unwrap_or(false);
            let escaped = protocol_graph_mermaid_escape(label);
            if initial {
                output.push_str(&format!("  {}((\"{}\"))\n", mermaid_id, escaped));
            } else if terminal {
                output.push_str(&format!("  {}[[\"{}\"]]\n", mermaid_id, escaped));
            } else {
                output.push_str(&format!("  {}[\"{}\"]\n", mermaid_id, escaped));
            }
        }
    }
    if let Some(edges) = graph.get("edges").and_then(serde_json::Value::as_array) {
        for edge in edges {
            let Some(source) = edge.get("source_vertex").and_then(serde_json::Value::as_str).and_then(|id| ids.get(id)) else {
                continue;
            };
            let Some(target) = edge.get("target_vertex").and_then(serde_json::Value::as_str).and_then(|id| ids.get(id)) else {
                continue;
            };
            let action = edge.get("action_name").and_then(serde_json::Value::as_str).unwrap_or("action");
            let label = match (
                edge.get("role").and_then(serde_json::Value::as_str),
                edge.get("role_source").and_then(serde_json::Value::as_str),
            ) {
                (Some(role), Some(source)) => format!("{action} · {role} via {source}"),
                _ => format!("{action} · role unknown"),
            };
            output.push_str(&format!("  {} -->|{}| {}\n", source, protocol_graph_mermaid_escape(&label), target));
        }
    }
    output
}

fn protocol_graph_mermaid_escape(label: &str) -> String {
    label.replace('\\', "\\\\").replace('"', "\\\"").replace('|', " ")
}

fn audit_bundle_json(metadata: &CompileMetadata) -> serde_json::Value {
    // Source-to-codegen mapping: link ProofPlan records to source spans, IR effects, and codegen coverage
    let source_to_codegen = metadata
        .runtime
        .proof_plan
        .iter()
        .map(|plan| {
            serde_json::json!({
                "origin": plan.origin,
                "feature": plan.feature,
                "status": plan.status,
                "source_span": plan.source_span.as_ref().map(|span| serde_json::json!({
                    "start": span.start,
                    "end": span.end,
                    "line": span.line,
                    "column": span.column,
                })).unwrap_or(serde_json::Value::Null),
                "trigger": plan.trigger,
                "scope": plan.scope,
                "codegen_coverage_status": plan.codegen_coverage_status,
                "on_chain_checked": plan.on_chain_checked,
                "ir_effect_class": match plan.category.as_str() {
                    "cell-access" => "cell-read-write",
                    "transaction-invariant" => "transaction-scan",
                    "declared-invariant" => "metadata-only-invariant",
                    "aggregate-invariant" => "aggregate-check",
                    "pool-primitive" => "pool-operation",
                    _ => "unknown",
                },
                "reads": plan.reads,
                "coverage": plan.coverage,
                "builder_assumptions": plan.builder_assumptions,
                "diagnostics": plan.diagnostics.iter().map(|diag| serde_json::json!({
                    "severity": diag.severity,
                    "message": diag.message,
                })).collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();

    // Action-level source-to-IR-to-codegen trace
    let action_traces = metadata
        .actions
        .iter()
        .map(|action| {
            serde_json::json!({
                "name": action.name,
                "estimated_cycles": action.estimated_cycles,
                "proof_plan_records": action.proof_plan.len(),
                "proof_plan_source_mappings": action.proof_plan.iter().map(|plan| serde_json::json!({
                    "origin": plan.origin,
                    "feature": plan.feature,
                    "source_span": plan.source_span,
                    "codegen_coverage_status": plan.codegen_coverage_status,
                })).collect::<Vec<_>>(),
                "runtime_accesses": action.ckb_runtime_accesses.iter().map(|access| serde_json::json!({
                    "source": access.source,
                    "operation": access.operation,
                    "index": access.index,
                    "binding": access.binding,
                    "provenance": access.provenance,
                })).collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();

    // Lock-level source-to-codegen trace
    let lock_traces = metadata
        .locks
        .iter()
        .map(|lock| {
            serde_json::json!({
                "name": lock.name,
                "proof_plan_records": lock.proof_plan.len(),
                "proof_plan_source_mappings": lock.proof_plan.iter().map(|plan| serde_json::json!({
                    "origin": plan.origin,
                    "feature": plan.feature,
                    "source_span": plan.source_span,
                    "codegen_coverage_status": plan.codegen_coverage_status,
                })).collect::<Vec<_>>(),
                "runtime_accesses": lock.ckb_runtime_accesses.iter().map(|access| serde_json::json!({
                    "source": access.source,
                    "operation": access.operation,
                    "index": access.index,
                    "binding": access.binding,
                    "provenance": access.provenance,
                })).collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();

    serde_json::json!({
        "status": "ok",
        "schema": "cellscript-audit-bundle-v0.16",
        "module": metadata.module,
        "compiler_version": metadata.compiler_version,
        "metadata_schema_version": metadata.metadata_schema_version,
        "metadata_schema_versions": metadata_schema_versions_json(metadata),
        "target_profile": metadata.target_profile,
        "source_to_codegen": source_to_codegen,
        "proof_plan": metadata.runtime.proof_plan,
        "proof_plan_soundness": metadata.runtime.proof_plan_soundness,
        "protocol_graph": protocol_graph_json(metadata),
        "template_layouts": metadata.template_layouts,
        "builder_assumptions": metadata.runtime.builder_assumptions,
        "constraints": metadata.constraints,
        "actions": action_traces,
        "locks": lock_traces,
        "source_units": metadata.source_units,
        "lowering": metadata.lowering,
        "debug_info_sections": metadata.debug_info_sections,
    })
}

fn audit_bundle_html(bundle: &serde_json::Value) -> String {
    let module = bundle.get("module").and_then(serde_json::Value::as_str).unwrap_or("unknown");
    let status = bundle.pointer("/proof_plan_soundness/status").and_then(serde_json::Value::as_str).unwrap_or("unknown");
    format!(
        "<!doctype html><meta charset=\"utf-8\"><title>CellScript Audit Bundle</title>\
         <h1>CellScript Audit Bundle</h1><p>Module: {}</p><p>ProofPlan soundness: {}</p>\
         <pre>{}</pre>",
        module,
        status,
        serde_json::to_string_pretty(bundle).unwrap_or_else(|_| "{}".to_string())
    )
}

fn proof_plan_summary_json(proof_plan: &[ProofPlanMetadata]) -> serde_json::Value {
    let record_count = proof_plan.len();
    let on_chain_checked_count = proof_plan.iter().filter(|plan| plan.on_chain_checked).count();
    let runtime_required_count = proof_plan.iter().filter(|plan| plan.status == "runtime-required").count();
    let metadata_only_gap_count = proof_plan.iter().filter(|plan| plan.codegen_coverage_status == "gap:metadata-only").count();
    let fail_closed_count =
        proof_plan.iter().filter(|plan| plan.status == "fail-closed" || plan.codegen_coverage_status == "fail-closed").count();
    let diagnostic_error_count =
        proof_plan.iter().flat_map(|plan| &plan.diagnostics).filter(|diagnostic| diagnostic.severity == "error").count();
    let diagnostic_warning_count =
        proof_plan.iter().flat_map(|plan| &plan.diagnostics).filter(|diagnostic| diagnostic.severity == "warning").count();
    let macro_provenance_count =
        proof_plan.iter().flat_map(|plan| &plan.coverage).filter(|coverage| coverage.starts_with("macro_expansion:")).count();
    let has_runtime_required_gaps = proof_plan.iter().any(|plan| plan.status == "runtime-required" && !plan.on_chain_checked);
    let has_fail_closed_gaps = fail_closed_count > 0;
    let evidence_tier_counts = crate::EvidenceTier::ALL
        .into_iter()
        .map(|tier| (tier.as_str().to_string(), proof_plan.iter().filter(|plan| plan.evidence_tier == tier).count()))
        .collect::<BTreeMap<_, _>>();

    serde_json::json!({
        "record_count": record_count,
        "on_chain_checked_count": on_chain_checked_count,
        "runtime_required_count": runtime_required_count,
        "metadata_only_gap_count": metadata_only_gap_count,
        "fail_closed_count": fail_closed_count,
        "diagnostic_error_count": diagnostic_error_count,
        "diagnostic_warning_count": diagnostic_warning_count,
        "macro_provenance_count": macro_provenance_count,
        "has_runtime_required_gaps": has_runtime_required_gaps,
        "has_fail_closed_gaps": has_fail_closed_gaps,
        "evidence_tier_counts": evidence_tier_counts,
        "has_blocking_diagnostics": has_runtime_required_gaps || has_fail_closed_gaps || diagnostic_error_count > 0,
    })
}

fn print_proof_plan_summary(proof_plan: &[ProofPlanMetadata]) {
    let summary = proof_plan_summary_json(proof_plan);
    println!("  Summary:");
    println!("    records: {}", summary["record_count"]);
    println!("    on_chain_checked: {}", summary["on_chain_checked_count"]);
    println!("    runtime_required: {}", summary["runtime_required_count"]);
    println!("    metadata_only_gaps: {}", summary["metadata_only_gap_count"]);
    println!("    fail_closed: {}", summary["fail_closed_count"]);
    println!("    diagnostic_errors: {}", summary["diagnostic_error_count"]);
    println!("    diagnostic_warnings: {}", summary["diagnostic_warning_count"]);
    println!("    macro_provenance_records: {}", summary["macro_provenance_count"]);
    println!("    evidence_tiers: {}", summary["evidence_tier_counts"]);
}

fn print_proof_plan_record(plan: &ProofPlanMetadata) {
    let coverage_notes = plan.coverage.iter().filter(|coverage| !coverage.starts_with("macro_expansion:")).collect::<Vec<_>>();
    let macro_provenance = plan.coverage.iter().filter(|coverage| coverage.starts_with("macro_expansion:")).collect::<Vec<_>>();

    println!();
    println!("constraint: {}", plan.name);
    println!("  origin: {}", plan.origin);
    println!("  evidence_tier: {}", plan.evidence_tier.as_str());
    println!("  trigger: {}", plan.trigger);
    println!("  scope: {}", plan.scope);
    println!("  reads:");
    if plan.reads.is_empty() {
        println!("    - none");
    } else {
        for read in &plan.reads {
            println!("    - {}", proof_plan_read_label(read));
        }
    }
    println!("  coverage:");
    if coverage_notes.is_empty() {
        println!("    - none");
    } else {
        for coverage in coverage_notes {
            println!("    - {}", coverage);
        }
    }
    if !macro_provenance.is_empty() {
        println!("  macro_provenance:");
        for provenance in macro_provenance {
            println!("    - {}", provenance);
        }
    }
    println!("  relation_checks:");
    if plan.input_output_relation_checks.is_empty() {
        println!("    - none");
    } else {
        for check in &plan.input_output_relation_checks {
            println!("    - {}", check);
        }
    }
    println!("  on_chain_checked: {}", if plan.on_chain_checked { "yes" } else { "no" });
    println!("  codegen_coverage_status: {}", plan.codegen_coverage_status);
    if !plan.witness_fields.is_empty() {
        println!("  witness_fields:");
        for field in &plan.witness_fields {
            println!("    - {}", field);
        }
    }
    if !plan.lock_args_fields.is_empty() {
        println!("  lock_args_fields:");
        for field in &plan.lock_args_fields {
            println!("    - {}", field);
        }
    }
    println!("  builder_assumption:");
    if plan.builder_assumptions.is_empty() {
        println!("    - none");
    } else {
        for assumption in &plan.builder_assumptions {
            println!("    - {}", assumption);
        }
    }
    for diagnostic in &plan.diagnostics {
        println!("  {}: {}", diagnostic.severity, diagnostic.message);
    }
}

fn proof_plan_read_label(read: &str) -> String {
    match read {
        "input" => "Source::Input".to_string(),
        "output" => "Source::Output".to_string(),
        "group_input" => "Source::GroupInput".to_string(),
        "group_output" => "Source::GroupOutput".to_string(),
        "cell_dep" => "Source::CellDep".to_string(),
        "header_dep" => "Source::HeaderDep".to_string(),
        "witness" => "WitnessArgs".to_string(),
        "lock_args" => "Script.args".to_string(),
        other => other.to_string(),
    }
}

fn resolution_options(
    features: &[String],
    all_features: bool,
    no_default_features: bool,
    environment: Option<&str>,
    offline: bool,
    frozen: bool,
    scope: crate::package::DependencyScope,
) -> crate::package::ResolutionOptions {
    crate::package::ResolutionOptions {
        scope,
        features: features.iter().cloned().collect(),
        all_features,
        no_default_features,
        environment: environment.map(str::to_string),
        offline: offline || frozen,
    }
}

fn build_resolution_options(args: &BuildArgs, scope: crate::package::DependencyScope) -> crate::package::ResolutionOptions {
    resolution_options(
        &args.features,
        args.all_features,
        args.no_default_features,
        args.environment.as_deref(),
        args.offline,
        args.frozen,
        scope,
    )
}

fn check_resolution_options(args: &CheckArgs, scope: crate::package::DependencyScope) -> crate::package::ResolutionOptions {
    resolution_options(
        &args.features,
        args.all_features,
        args.no_default_features,
        args.environment.as_deref(),
        args.offline,
        args.frozen,
        scope,
    )
}

fn test_resolution_options(args: &TestArgs) -> crate::package::ResolutionOptions {
    resolution_options(
        &args.features,
        args.all_features,
        args.no_default_features,
        args.environment.as_deref(),
        args.offline,
        args.frozen,
        crate::package::DependencyScope::Test,
    )
}

fn effective_check_args(mut args: CheckArgs) -> Result<CheckArgs> {
    // In a workspace root (virtual manifest without [package]), fall back to default policy.
    let policy = PackageManager::new(".").read_manifest().map(|m| m.policy).unwrap_or_default();
    merge_check_policy(&mut args, &policy);
    Ok(args)
}

fn effective_check_target_profile(args: &CheckArgs) -> Result<TargetProfile> {
    if let Some(profile) = args.target_profile.as_deref() {
        return TargetProfile::from_name(profile);
    }

    if let Some(profile) = manifest_target_profile()? {
        return Ok(profile);
    }

    Ok(TargetProfile::Ckb)
}

fn manifest_target_profile() -> Result<Option<TargetProfile>> {
    let manifest_path = Path::new("Cell.toml");
    if !manifest_path.exists() {
        return Ok(None);
    }

    let source = std::fs::read_to_string(manifest_path).map_err(|error| {
        crate::error::CompileError::without_span(format!("failed to read Cell.toml target profile policy: {}", error))
    })?;
    let manifest: toml::Value = toml::from_str(&source).map_err(|error| {
        crate::error::CompileError::without_span(format!("failed to parse Cell.toml target profile policy: {}", error))
    })?;
    let Some(profile) = manifest.get("build").and_then(|build| build.get("target_profile")).and_then(toml::Value::as_str) else {
        return Ok(None);
    };
    TargetProfile::from_name(profile).map(Some)
}

fn compile_target_profile_for_check(profile: TargetProfile) -> Option<String> {
    match profile {
        TargetProfile::Ckb => Some(TargetProfile::Ckb.name().to_string()),
    }
}

fn display_doc_output_format(format: &OutputFormat) -> &'static str {
    match format {
        OutputFormat::Html => "html",
        OutputFormat::Markdown => "markdown",
        OutputFormat::Json => "json",
    }
}

fn ensure_new_package_destination(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }

    let mut entries = std::fs::read_dir(path)
        .map_err(|error| crate::error::CompileError::without_span(format!("failed to inspect '{}': {}", path.display(), error)))?;
    if entries.next().is_none() {
        return Ok(());
    }

    Err(crate::error::CompileError::without_span(format!("destination '{}' already exists and is not empty", path.display())))
}

fn init_git_repo(path: &Path) -> Result<bool> {
    // Absolute destinations are supported by `cellc new`; `--` keeps a
    // destination beginning with '-' from being interpreted as a git option.
    let output = std::process::Command::new("git").arg("init").arg("--quiet").arg("--").arg(path).output().map_err(|error| {
        crate::error::CompileError::without_span(format!("failed to run git init for '{}': {}", path.display(), error))
    })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(crate::error::CompileError::without_span(format!("git init failed for '{}': {}", path.display(), stderr.trim())));
    }
    Ok(true)
}

fn runtime_error_info_from_query(query: &str) -> Option<CellScriptRuntimeErrorInfo> {
    let trimmed = query.trim().trim_matches('`');
    let numeric = trimmed
        .parse::<u64>()
        .ok()
        .or_else(|| trimmed.strip_prefix('E').or_else(|| trimmed.strip_prefix('e')).and_then(|code| code.parse::<u64>().ok()));

    if let Some(code) = numeric {
        return runtime_error_info_by_code(code);
    }

    ALL_RUNTIME_ERRORS.iter().copied().map(runtime_error_info).find(|info| info.name == trimmed)
}

fn validate_dependency_target_flags(dev: bool, build: bool) -> Result<()> {
    if dev && build {
        return Err(crate::error::CompileError::without_span("dependency target flags --dev and --build are mutually exclusive"));
    }
    if build {
        return Err(crate::error::CompileError::without_span(
            "--build dependencies are reserved until isolated build-script execution is implemented",
        ));
    }
    Ok(())
}

/// Reject self-dependency writes to the manifest. A package cannot list itself
/// (or a path pointing at its own root) as a dependency because that turns the
/// package graph into an immediate cycle. The empty-name edge case observed in
/// 0.20 ("cellc install --path ." wrote a `[dependencies.""]` row that broke
/// every subsequent `cellc build`) is the canonical failure this helper
/// prevents.
fn validate_not_self_dependency(crate_name: &str, dep: &Dependency, manifest: &crate::package::PackageManifest) -> Result<()> {
    if !crate_name.trim().is_empty() && crate_name == manifest.package.name {
        return Err(crate::error::CompileError::without_span(format!(
            "refusing to add self-dependency: package '{}' cannot depend on itself",
            manifest.package.name
        )));
    }
    if let Dependency::Detailed(detailed) = dep
        && let Some(dep_path) = &detailed.path
    {
        let dep_canon = std::path::Path::new(dep_path);
        let manifest_dir = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
        let dep_abs = dep_canon.canonicalize().unwrap_or_else(|_| manifest_dir.join(dep_canon));
        let manifest_abs = manifest_dir.canonicalize().unwrap_or_else(|_| manifest_dir.clone());
        if dep_abs == manifest_abs {
            return Err(crate::error::CompileError::without_span(format!(
                "refusing to add self-dependency: path '{}' resolves to the current package root",
                dep_path
            )));
        }
    }
    Ok(())
}

fn dependency_target_label(dev: bool, build: bool) -> &'static str {
    if build {
        "build-dependencies"
    } else if dev {
        "dev-dependencies"
    } else {
        "dependencies"
    }
}

fn dependency_map_mut(manifest: &mut crate::package::PackageManifest, dev: bool, build: bool) -> &mut HashMap<String, Dependency> {
    if build {
        &mut manifest.build.dependencies
    } else if dev {
        &mut manifest.dev_dependencies
    } else {
        &mut manifest.dependencies
    }
}

fn dependency_from_add_args(args: &AddArgs) -> Dependency {
    match (&args.git, &args.path) {
        (Some(git), _) => Dependency::Detailed(DetailedDependency {
            version: "*".to_string(),
            namespace: None,
            package: args.package.clone(),
            resolver: None,
            git: Some(git.clone()),
            branch: None,
            tag: None,
            rev: None,
            path: None,
            optional: false,
            features: Vec::new(),
            default_features: true,
            use_environment: args.use_environment.clone(),
            environment_independent: args.environment_independent,
            allow_unverified: false,
            allow_quarantined: false,
        }),
        (_, Some(path)) => Dependency::Detailed(DetailedDependency {
            version: "*".to_string(),
            namespace: None,
            package: args.package.clone(),
            resolver: None,
            git: None,
            branch: None,
            tag: None,
            rev: None,
            path: Some(path.display().to_string()),
            optional: false,
            features: Vec::new(),
            default_features: true,
            use_environment: args.use_environment.clone(),
            environment_independent: args.environment_independent,
            allow_unverified: false,
            allow_quarantined: false,
        }),
        _ if args.package.is_some() || args.use_environment.is_some() || args.environment_independent => {
            Dependency::Detailed(DetailedDependency {
                version: "*".to_string(),
                namespace: None,
                package: args.package.clone(),
                resolver: None,
                git: None,
                branch: None,
                tag: None,
                rev: None,
                path: None,
                optional: false,
                features: Vec::new(),
                default_features: true,
                use_environment: args.use_environment.clone(),
                environment_independent: args.environment_independent,
                allow_unverified: false,
                allow_quarantined: false,
            })
        }
        _ => Dependency::Simple("*".to_string()),
    }
}

fn auth_capability_args_from_matches(m: &clap::ArgMatches) -> AuthCapabilityArgs {
    AuthCapabilityArgs {
        registry_origin: m.get_one::<String>("registry-origin").cloned(),
        principal_type: m.get_one::<String>("principal-type").cloned(),
        principal_id: m.get_one::<String>("principal-id").cloned(),
        capability_pubkey: m.get_one::<String>("capability-pubkey").cloned(),
        scopes: m.get_many::<String>("scope").map(|values| values.cloned().collect()).unwrap_or_default(),
        expires: m.get_one::<String>("expires").cloned(),
        capability_expires_at: m.get_one::<String>("capability-expires-at").cloned(),
        json: json_output(m),
    }
}

fn auth_capability_submit_args_from_matches(m: &clap::ArgMatches) -> AuthCapabilitySubmitArgs {
    AuthCapabilitySubmitArgs {
        api_url: m.get_one::<String>("api-url").cloned(),
        payload: m.get_one::<String>("payload").map(PathBuf::from).expect("required payload"),
        wallet_signature: m.get_one::<String>("wallet-signature").map(PathBuf::from).expect("required wallet-signature"),
        json: json_output(m),
    }
}

fn auth_reproducer_create_args_from_matches(m: &clap::ArgMatches) -> AuthReproducerCreateArgs {
    AuthReproducerCreateArgs {
        builder_id: m.get_one::<String>("builder-id").cloned().expect("required builder-id"),
        trust_domain: m.get_one::<String>("trust-domain").cloned().expect("required trust-domain"),
        private_key_output: m.get_one::<String>("private-key-output").map(PathBuf::from),
        json: json_output(m),
    }
}

fn auth_namespace_claim_args_from_matches(m: &clap::ArgMatches) -> AuthNamespaceClaimArgs {
    AuthNamespaceClaimArgs {
        api_url: m.get_one::<String>("api-url").cloned(),
        namespace: m.get_one::<String>("namespace").cloned().expect("required namespace"),
        payload: m.get_one::<String>("payload").map(PathBuf::from).expect("required payload"),
        wallet_signature: m.get_one::<String>("wallet-signature").map(PathBuf::from).expect("required wallet-signature"),
        json: json_output(m),
    }
}

fn auth_capability_revoke_args_from_matches(m: &clap::ArgMatches) -> AuthCapabilityRevokeArgs {
    AuthCapabilityRevokeArgs {
        api_url: m.get_one::<String>("api-url").cloned(),
        registry_origin: m.get_one::<String>("registry-origin").cloned(),
        principal_type: m.get_one::<String>("principal-type").cloned(),
        principal_id: m.get_one::<String>("principal-id").cloned(),
        capability_key_id: m.get_one::<String>("capability-key-id").cloned(),
        payload: m.get_one::<String>("payload").map(PathBuf::from),
        wallet_signature: m.get_one::<String>("wallet-signature").map(PathBuf::from),
        reason: m.get_one::<String>("reason").cloned(),
        json: json_output(m),
    }
}

fn refresh_lockfile_from_manifest(root: &Path) -> Result<()> {
    let manager = PackageManager::new(root);
    let manifest = manager.read_manifest()?;
    let mut lockfile = read_lockfile_for_explicit_repin(root)?;
    lockfile.dependencies.clear();
    lockfile.root = crate::package::LockedRootGraph::default();
    lockfile.environments.clear();
    lockfile.package = lockfile_package_info(root, &manifest)?;

    let mut environments: Vec<Option<String>> = Vec::new();
    if manifest.dependency_overrides.is_empty() {
        environments.push(None);
    }
    environments.extend(manifest.environments.keys().cloned().map(Some));
    for environment in environments {
        let mut manager = PackageManager::new(root);
        let options = crate::package::ResolutionOptions {
            scope: crate::package::DependencyScope::Test,
            all_features: true,
            environment,
            ..crate::package::ResolutionOptions::default()
        };
        manager.resolve_dependencies_with_options(&options)?;
        lockfile.merge_resolution(&manager, &manifest, &options)?;
    }
    lockfile.write_to_root(root)?;
    Ok(())
}

fn read_lockfile_for_explicit_repin(root: &Path) -> Result<Lockfile> {
    match Lockfile::read_from_root(root) {
        Ok(Some(lockfile)) => Ok(lockfile),
        Ok(None) => Ok(Lockfile::new()),
        Err(error) => {
            let path = root.join("Cell.lock");
            let source = std::fs::read_to_string(&path).map_err(|_| error.clone())?;
            let value: toml::Value = toml::from_str(&source).map_err(|_| error.clone())?;
            if value.get("version").and_then(toml::Value::as_integer).is_some_and(|version| matches!(version, 1 | 2)) {
                Ok(Lockfile::new())
            } else {
                Err(error)
            }
        }
    }
}

fn refresh_lockfile_from_build(root: &Path, metadata: &CompileMetadata) -> Result<()> {
    let manager = PackageManager::new(root);
    let manifest = manager.read_manifest()?;

    let mut lockfile = Lockfile::read_from_root(root)?.unwrap_or_default();
    if (!manifest.dependencies.is_empty() || !manifest.dev_dependencies.is_empty()) && lockfile.root.manifest_digest.is_empty() {
        return Err(crate::error::CompileError::without_span(
            "Cell.lock has no pinned dependency graph; run 'cellc lock' or 'cellc update' before building",
        ));
    }
    if manifest.dependencies.is_empty() && manifest.dev_dependencies.is_empty() {
        lockfile.root.manifest_digest = crate::package::compute_manifest_digest(root)?;
    }
    let mut package = lockfile_package_info(root, &manifest)?;
    package.compiler_source_hash = metadata.source_hash.clone();
    lockfile.package = package;
    lockfile.package_build = Some(locked_build_info_from_metadata(metadata)?);
    refresh_lockfile_deployment_refs(root, &mut lockfile);
    lockfile.write_to_root(root)?;
    Ok(())
}

/// Bridge Deployed.toml deployment records into Cell.lock. Without this,
/// `cellc registry verify` would always fail with "deployment for network 'X'
/// is missing from Cell.lock" because nothing in the production build pipeline
/// ever wrote a `lockfile.deployment` entry. We only keep a record if its
/// deployment name + tx_hash + output_index match a real Deployed.toml entry;
/// stale or duplicate networks are dropped. Records that fail the build-identity
/// match (artifact_hash / metadata_hash / etc. mismatch with Cell.lock's locked
/// build) are kept but their hash fields are left None so the registry verifier
/// can surface the mismatch as a violation instead of pretending the deployment
/// is consistent with the locked build.
fn refresh_lockfile_deployment_refs(root: &Path, lockfile: &mut crate::package::Lockfile) {
    let deployed = match crate::package::DeployedManifest::read_from_root(root) {
        Ok(Some(manifest)) => manifest,
        Ok(None) => return,
        Err(_) => return,
    };
    let locked_build = lockfile.package_build.as_ref();
    let mut next: BTreeMap<String, crate::package::LockfileDeploymentRef> = BTreeMap::new();
    for record in deployed.deployments {
        if record.network.trim().is_empty() {
            continue;
        }
        if next.contains_key(&record.network) {
            // First-write wins; later duplicates from Deployed.toml are dropped
            // to keep Cell.lock deterministic for the same source tree.
            continue;
        }
        let artifact_match = match (&record.artifact_hash, locked_build.and_then(|b| b.artifact_hash.as_ref())) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        };
        let record_str = record.out_point.clone();
        let record_hash = if artifact_match { hash_json_value("deployment record", &record).ok() } else { None };
        let code_hash = if artifact_match { Some(record.code_hash.clone()) } else { None };
        let out_point = if artifact_match { Some(record.out_point.clone()) } else { None };
        let data_hash = if artifact_match { Some(record.data_hash.clone()) } else { None };
        next.insert(
            record.network.clone(),
            crate::package::LockfileDeploymentRef { record: record_str, record_hash, code_hash, out_point, data_hash },
        );
    }
    lockfile.deployment = next;
}

fn lockfile_package_info(root: &Path, manifest: &crate::package::PackageManifest) -> Result<crate::package::LockfilePackageInfo> {
    Ok(crate::package::LockfilePackageInfo {
        edition: manifest.package.edition,
        name: manifest.package.name.clone(),
        version: manifest.package.version.clone(),
        namespace: manifest.package.namespace.clone(),
        source_hash: Some(crate::package::registry::compute_source_hash(root)?),
        compiler_source_hash: None,
    })
}

fn locked_build_info_from_metadata(metadata: &CompileMetadata) -> Result<crate::package::LockedBuildInfo> {
    Ok(crate::package::LockedBuildInfo {
        edition: metadata.edition,
        compatibility_profile_hash: hash_json_value("compatibility_profile", &metadata.compatibility_profile)?,
        compiler_version: Some(metadata.compiler_version.clone()),
        target_profile: Some(metadata.target_profile.name.clone()),
        artifact_hash: metadata.artifact_hash.clone(),
        metadata_hash: Some(hash_json_value("metadata", metadata)?),
        schema_hash: Some(metadata.molecule_schema_manifest.manifest_hash.clone()),
        cell_data_codec_manifest_hash: Some(metadata.cell_data_codec_manifest.manifest_hash.clone()),
        abi_hash: Some(metadata_abi_hash(metadata)?),
        constraints_hash: Some(hash_json_value("constraints", &metadata.constraints)?),
    })
}

fn metadata_schema_versions_json(metadata: &CompileMetadata) -> serde_json::Value {
    serde_json::json!({
        "metadata": metadata.metadata_schema_version,
        "source": metadata.source_metadata_schema_version,
        "artifact": metadata.artifact_metadata_schema_version,
        "constraints": metadata.constraints_metadata_schema_version,
    })
}

fn metadata_abi_hash(metadata: &CompileMetadata) -> Result<String> {
    let abi = serde_json::json!({
        "metadata_schema_version": metadata.metadata_schema_version,
        "metadata_schema_versions": metadata_schema_versions_json(metadata),
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
    hash_json_value("abi", &abi)
}

fn hash_json_value<T: serde::Serialize>(label: &str, value: &T) -> Result<String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|e| crate::error::CompileError::without_span(format!("failed to serialize {} for digest: {}", label, e)))?;
    Ok(crate::hex_encode(&crate::ckb_blake2b256(&bytes)))
}

struct CompileReceiptVerificationReport {
    payload_hash: String,
    signatures_verified: usize,
    unsigned_advisory: bool,
}

fn compile_receipt_json(metadata: &CompileMetadata) -> Result<serde_json::Value> {
    let proof_plan_hash = hash_json_value("proof_plan", &metadata.runtime.proof_plan)?;
    let protocol_graph = protocol_graph_json(metadata);
    let protocol_graph_hash = hash_json_value("protocol_graph", &protocol_graph)?;
    let template_layout_hash = if metadata.template_layouts.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::Value::String(hash_json_value("template_layouts", &metadata.template_layouts)?)
    };
    Ok(serde_json::json!({
        "schema": "cellscript-compile-receipt-v2",
        "compiler_version": metadata.compiler_version,
        "edition": metadata.edition,
        "compatibility_profile": metadata.compatibility_profile,
        "compatibility_profile_hash": hash_json_value("compatibility_profile", &metadata.compatibility_profile)?,
        "rust_toolchain": cellscript_rust_toolchain(),
        "target": metadata.artifact_format,
        "target_profile": metadata.target_profile.name,
        "source_hash": metadata.source_hash,
        "source_content_hash": metadata.source_content_hash,
        "ast_normalised_hash": serde_json::Value::Null,
        "ir_normalised_hash": serde_json::Value::Null,
        "normalisation_status": "ast-ir-normalised-hashes-not-yet-emitted",
        "proof_plan_hash": proof_plan_hash,
        "protocol_graph_hash": protocol_graph_hash,
        "template_layout_hash": template_layout_hash,
        "artifact_hash": metadata.artifact_hash,
        "metadata_hash": hash_json_value("metadata", metadata)?,
        "metadata_schema_version": metadata.metadata_schema_version,
        "metadata_schema_versions": metadata_schema_versions_json(metadata),
        "signatures": [],
    }))
}

fn verify_compile_receipt_against_metadata(
    receipt: &serde_json::Value,
    metadata: &CompileMetadata,
) -> Result<CompileReceiptVerificationReport> {
    validate_compile_receipt_schema(receipt)?;
    let expected = compile_receipt_json(metadata)?;
    for pointer in [
        "/compiler_version",
        "/edition",
        "/compatibility_profile",
        "/compatibility_profile_hash",
        "/rust_toolchain",
        "/target",
        "/target_profile",
        "/source_hash",
        "/source_content_hash",
        "/ast_normalised_hash",
        "/ir_normalised_hash",
        "/normalisation_status",
        "/proof_plan_hash",
        "/protocol_graph_hash",
        "/template_layout_hash",
        "/artifact_hash",
        "/metadata_hash",
        "/metadata_schema_version",
        "/metadata_schema_versions",
    ] {
        if receipt.pointer(pointer) != expected.pointer(pointer) {
            return Err(crate::error::CompileError::without_span(format!(
                "compile receipt field '{}' does not match validated metadata/artifact evidence",
                pointer.trim_start_matches('/')
            )));
        }
    }
    verify_compile_receipt_signatures(receipt)
}

fn validate_compile_receipt_schema(receipt: &serde_json::Value) -> Result<()> {
    match receipt.get("schema").and_then(serde_json::Value::as_str) {
        Some("cellscript-compile-receipt-v2") => Ok(()),
        Some(schema) => Err(crate::error::CompileError::without_span(format!(
            "unsupported compile receipt schema '{}'; expected cellscript-compile-receipt-v2",
            schema
        ))),
        None => Err(crate::error::CompileError::without_span("compile receipt is missing schema")),
    }
}

fn compile_receipt_payload_hash(receipt: &serde_json::Value) -> Result<String> {
    let mut unsigned = receipt.clone();
    let object = unsigned
        .as_object_mut()
        .ok_or_else(|| crate::error::CompileError::without_span("compile receipt must be a JSON object before it can be hashed"))?;
    object.remove("signatures");
    hash_json_value("compile receipt signing payload", &unsigned)
}

fn verify_compile_receipt_signatures(receipt: &serde_json::Value) -> Result<CompileReceiptVerificationReport> {
    let payload_hash = compile_receipt_payload_hash(receipt)?;
    let signatures = match receipt.get("signatures") {
        None => return Ok(CompileReceiptVerificationReport { payload_hash, signatures_verified: 0, unsigned_advisory: true }),
        Some(serde_json::Value::Array(signatures)) => signatures,
        Some(_) => {
            return Err(crate::error::CompileError::without_span("compile receipt signatures field must be an array when present"));
        }
    };
    if signatures.is_empty() {
        return Ok(CompileReceiptVerificationReport { payload_hash, signatures_verified: 0, unsigned_advisory: true });
    }

    for (index, signature) in signatures.iter().enumerate() {
        let prefix = format!("compile receipt signatures[{index}]");
        let algorithm = signature
            .get("algorithm")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| crate::error::CompileError::without_span(format!("{prefix}.algorithm is required")))?;
        if algorithm != "ed25519" {
            return Err(crate::error::CompileError::without_span(format!(
                "{prefix}.algorithm '{}' is unsupported; expected ed25519",
                algorithm
            )));
        }
        let signature_payload_hash = signature
            .get("payload_hash")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| crate::error::CompileError::without_span(format!("{prefix}.payload_hash is required")))?;
        if signature_payload_hash != payload_hash {
            return Err(crate::error::CompileError::without_span(format!(
                "{prefix}.payload_hash does not match current compile receipt payload hash"
            )));
        }
        let public_key = decode_prefixed_base64_field(signature, "public_key", "ed25519-pk:", &prefix)?;
        let signature_bytes = decode_prefixed_base64_field(signature, "signature", "ed25519-sig:", &prefix)?;
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public_key)
            .verify(payload_hash.as_bytes(), &signature_bytes)
            .map_err(|_| crate::error::CompileError::without_span(format!("{prefix}.signature failed Ed25519 verification")))?;
    }

    Ok(CompileReceiptVerificationReport { payload_hash, signatures_verified: signatures.len(), unsigned_advisory: false })
}

fn decode_prefixed_base64_field(value: &serde_json::Value, field: &str, prefix: &str, diagnostic_prefix: &str) -> Result<Vec<u8>> {
    let text = value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| crate::error::CompileError::without_span(format!("{diagnostic_prefix}.{field} is required")))?;
    let encoded = text
        .strip_prefix(prefix)
        .ok_or_else(|| crate::error::CompileError::without_span(format!("{diagnostic_prefix}.{field} must start with '{prefix}'")))?;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(encoded).map_err(|error| {
        crate::error::CompileError::without_span(format!("{diagnostic_prefix}.{field} has invalid base64url payload: {error}"))
    })
}

fn read_ed25519_pkcs8_key_arg(key: &str) -> Result<Vec<u8>> {
    let key = key.trim();
    if key.is_empty() {
        return Err(crate::error::CompileError::without_span("receipt signing key must be non-empty"));
    }
    let path = key.strip_prefix('@').unwrap_or(key);
    if Path::new(path).exists() {
        return std::fs::read(path)
            .map_err(|error| crate::error::CompileError::without_span(format!("failed to read Ed25519 key '{}': {}", path, error)));
    }
    let encoded = key.strip_prefix("ed25519-pkcs8:").or_else(|| key.strip_prefix("base64:")).unwrap_or(key);
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(encoded))
        .map_err(|error| {
            crate::error::CompileError::without_span(format!(
                "receipt signing key must be a file path or base64 Ed25519 PKCS#8 DER: {}",
                error
            ))
        })
}

fn validate_receipt_signature_role(role: &str) -> Result<&str> {
    match role {
        "compiler" | "publisher" => Ok(role),
        other => Err(crate::error::CompileError::without_span(format!(
            "unsupported receipt signature role '{}'; expected compiler or publisher",
            other
        ))),
    }
}

fn cellscript_rust_toolchain() -> String {
    include_str!("../../Cargo.toml")
        .lines()
        .find_map(|line| {
            let line = line.trim();
            line.strip_prefix("rust-version")
                .and_then(|rest| rest.split_once('='))
                .map(|(_, value)| value.trim().trim_matches('"').to_string())
        })
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn action_scan_selectors_json(action: &crate::ActionMetadata) -> serde_json::Value {
    let runtime_required_selector_count =
        action.transaction_runtime_input_requirements.iter().filter(|requirement| requirement.status == "runtime-required").count();
    let checked_runtime_selector_count =
        action.transaction_runtime_input_requirements.iter().filter(|requirement| requirement.status == "checked-runtime").count();
    let ckb_sources = action
        .transaction_runtime_input_requirements
        .iter()
        .map(|requirement| requirement.source.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let selectors = action
        .transaction_runtime_input_requirements
        .iter()
        .enumerate()
        .map(|(index, requirement)| action_scan_selector_json(action, index, requirement))
        .collect::<Vec<_>>();

    serde_json::json!({
        "schema": "cellscript-action-scan-selectors-v0.21",
        "status": action_scan_selector_status(selectors.len(), runtime_required_selector_count),
        "evidence_level": "compile-only",
        "source": "transaction_runtime_input_requirements",
        "action": action.name,
        "selector_count": selectors.len(),
        "checked_runtime_selector_count": checked_runtime_selector_count,
        "runtime_required_selector_count": runtime_required_selector_count,
        "ckb_sources": ckb_sources,
        "selectors": selectors,
        "non_claims": [
            "does-not-query-live-cells",
            "does-not-bind-outpoints",
            "does-not-prove-ckb-vm-execution",
            "does-not-prove-tx-pool-acceptance"
        ],
    })
}

fn action_scan_selector_status(selector_count: usize, runtime_required_selector_count: usize) -> &'static str {
    if selector_count == 0 {
        "no-action-scans-required"
    } else if runtime_required_selector_count == 0 {
        "compile-checked-runtime-selectors"
    } else {
        "requires-runtime-resolution"
    }
}

fn action_scan_selector_json(
    action: &crate::ActionMetadata,
    index: usize,
    requirement: &crate::TransactionRuntimeInputRequirementMetadata,
) -> serde_json::Value {
    serde_json::json!({
        "selector_index": index,
        "requirement_index": index,
        "action": action.name,
        "scope": requirement.scope,
        "feature": requirement.feature,
        "component": requirement.component,
        "requirement_status": requirement.status,
        "scan_status": action_scan_requirement_status(requirement),
        "ckb_source": requirement.source,
        "role": action_scan_source_role(&requirement.source),
        "binding": requirement.binding,
        "field": requirement.field,
        "abi": requirement.abi,
        "byte_len": requirement.byte_len,
        "script_field": action_scan_script_field(requirement),
        "script_args": serde_json::Value::Null,
        "args_pattern": action_scan_args_pattern(requirement),
        "selector": {
            "kind": action_scan_kind(&requirement.source),
            "source": requirement.source,
            "binding": requirement.binding,
            "field": requirement.field,
            "component": requirement.component,
            "abi": requirement.abi,
        },
        "resolution": {
            "status": action_scan_requirement_status(requirement),
            "blocker": requirement.blocker,
            "blocker_class": requirement.blocker_class,
            "adapter_action": action_scan_adapter_action(requirement),
        },
    })
}

fn action_scan_requirement_status(requirement: &crate::TransactionRuntimeInputRequirementMetadata) -> &'static str {
    if requirement.status == "runtime-required" {
        "requires-runtime-resolution"
    } else {
        "verifier-covered"
    }
}

fn action_scan_source_role(source: &str) -> &'static str {
    match source {
        "Input" => "transaction-input-live-cell",
        "Output" => "transaction-output",
        "InputOutput" => "paired-input-output",
        "CellDep" => "cell-dep",
        "HeaderDep" => "header-dep",
        "Transaction" => "whole-transaction",
        _ => "runtime-transaction-component",
    }
}

fn action_scan_kind(source: &str) -> &'static str {
    match source {
        "Input" => "input-cell-selector",
        "Output" => "output-cell-selector",
        "InputOutput" => "input-output-pair-selector",
        "CellDep" => "cell-dep-selector",
        "HeaderDep" => "header-dep-selector",
        "Transaction" => "transaction-selector",
        _ => "transaction-component-selector",
    }
}

fn action_scan_script_field(requirement: &crate::TransactionRuntimeInputRequirementMetadata) -> Option<&'static str> {
    match requirement.field.as_deref() {
        Some("lock_hash") => Some("lock"),
        Some("identity" | "ckb_type_script_hash-absence") => Some("type"),
        _ => None,
    }
}

fn action_scan_args_pattern(requirement: &crate::TransactionRuntimeInputRequirementMetadata) -> &'static str {
    if action_scan_script_field(requirement).is_some() {
        "runtime-supplied-from-resolved-script"
    } else {
        "not-applicable"
    }
}

fn action_scan_adapter_action(requirement: &crate::TransactionRuntimeInputRequirementMetadata) -> &'static str {
    if requirement.status == "runtime-required" {
        "resolve-or-reject-before-signing"
    } else {
        "materialize-and-preserve-verifier-covered-shape"
    }
}

fn cellfabric_intent_envelope_json(
    metadata: &CompileMetadata,
    action: &crate::ActionMetadata,
    action_plan: &serde_json::Value,
    input_path: &Path,
    metadata_hash: &str,
) -> Result<serde_json::Value> {
    let action_plan_hash = hash_json_value("CellScript action plan", action_plan)?;
    let app_namespace = metadata.module.clone();
    let app_conflict_key_templates = cellfabric_app_conflict_key_templates(&app_namespace, action);
    Ok(serde_json::json!({
        "schema": "cellscript-cellfabric-intent-envelope-v0.20",
        "status": "requires-runtime-binding",
        "bridge_boundary": {
            "kind": "json-bridge",
            "cellscript_core_dependency": "no-cell-fabric-rust-crate",
            "cellfabric_expected_role": "intent-ordering-soft-confirmation-and-settlement-tracking",
            "not_a_cellfabric_signed_intent": true,
            "not_a_soft_confirmation": true,
            "not_l1_finality": true,
            "compiler_must_not_infer_cellfabric_finality": true,
        },
        "source": {
            "input": input_path.display().to_string(),
            "module": metadata.module.clone(),
            "action": action.name.clone(),
            "target_profile": metadata.target_profile.name.clone(),
            "compiler_version": metadata.compiler_version.clone(),
            "metadata_hash": metadata_hash,
            "artifact_hash": &metadata.artifact_hash,
            "action_plan_hash": action_plan_hash.clone(),
        },
        "cellfabric_mapping": {
            "target": "CellFabric IntentBody template",
            "candidate_intent_action": "App",
            "payload_format": "cellscript-action-plan-json-v1",
            "payload_hash_field": "cellscript_action_plan_hash",
            "resource_binding": "runtime-resolved-live-cells",
            "auth_binding": "runtime-wallet-or-live-cell-context",
            "settlement_compiler": "cellscript-ckb-adapter-or-generated-builder",
        },
        "cellfabric_intent_template": {
            "version": 1,
            "domain": {
                "chain_id": metadata.target_profile.name.clone(),
                "app_namespace": app_namespace.clone(),
            },
            "author": {
                "lock_script_hash": serde_json::Value::Null,
                "source": "runtime-wallet-or-live-cell-context",
            },
            "nonce": serde_json::Value::Null,
            "validity": {
                "valid_after_ms": serde_json::Value::Null,
                "valid_until_ms": serde_json::Value::Null,
            },
            "resources": {
                "consumes": [],
                "reads": [],
                "app_keys": app_conflict_key_templates,
                "status": "template-only-runtime-outpoints-required",
            },
            "action": {
                "kind": "App",
                "action": action.name.clone(),
                "payload_format": "cellscript-action-plan-json-v1",
                "payload_hash": action_plan_hash.clone(),
            },
            "constraints": {
                "source": "cellscript-action-plan",
                "runtime_input_requirements": &action.transaction_runtime_input_requirements,
                "verifier_obligations": &action.verifier_obligations,
                "fail_closed_runtime_features": &action.fail_closed_runtime_features,
            },
            "dependencies": {
                "requires": [],
                "source": "service-supplied-cellfabric-intent-ids",
            },
            "replacement": {
                "supersedes": [],
                "rule": "service-policy",
            },
            "fee": {
                "fee_bid_shannons": serde_json::Value::Null,
                "max_fee_shannons": serde_json::Value::Null,
                "source": "runtime-builder-policy",
            },
            "auth_mode": "CoSignConcreteTx",
            "metadata": {
                "cellscript_action": action.name.clone(),
                "cellscript_metadata_hash": metadata_hash,
                "cellscript_action_plan_hash": action_plan_hash.clone(),
                "cellscript_artifact_hash": &metadata.artifact_hash,
            },
        },
        "resource_access_template": {
            "hard_conflicts": {
                "status": "runtime-required",
                "consumed_cell_patterns": &action.consume_set,
                "runtime_input_requirements": &action.transaction_runtime_input_requirements,
                "note": "CellFabric OutPointRef conflicts must be filled from resolved live cells before submitting a SignedIntent.",
            },
            "reads": &action.read_refs,
            "writes": {
                "creates": &action.create_set,
                "mutates": &action.mutate_set,
            },
            "app_conflict_key_templates": cellfabric_app_conflict_key_templates(&app_namespace, action),
        },
        "required_runtime_evidence": [
            "author_lock_script_hash",
            "intent_nonce",
            "resolved_consumed_outpoints",
            "resolved_read_outpoints",
            "cellfabric_auth_signature",
            "deployment_identity",
            "live_cell_resolution",
            "capacity_fee_balance",
            "estimate_cycles",
            "tx_pool_acceptance",
            "l1_status_observation"
        ],
        "non_claims": [
            "does not create a CellFabric SignedIntent",
            "does not prove CellFabric orderer acceptance",
            "does not soft-confirm the action",
            "does not prove live-cell availability",
            "does not prove CKB tx-pool acceptance",
            "does not prove L1 finality"
        ],
        "action_plan": action_plan,
    }))
}

fn cellfabric_app_conflict_key_templates(app_namespace: &str, action: &crate::ActionMetadata) -> Vec<serde_json::Value> {
    let mut keys = BTreeSet::<(String, String)>::new();
    for shared in &action.touches_shared {
        keys.insert(("cellscript-shared-resource".to_string(), shared.clone()));
    }
    for pattern in &action.mutate_set {
        keys.insert(("cellscript-mutate-binding".to_string(), format!("{}:{}", pattern.ty, pattern.binding)));
    }
    for primitive in &action.pool_primitives {
        if let Ok(value) = serde_json::to_value(primitive) {
            keys.insert(("cellscript-pool-primitive".to_string(), value.to_string()));
        }
    }
    keys.into_iter()
        .map(|(key_type, key)| {
            serde_json::json!({
                "namespace": app_namespace,
                "key_type": key_type,
                "key": key,
                "key_encoding": "utf8",
                "key_bytes_hex": crate::hex_encode(key.as_bytes()),
            })
        })
        .collect()
}

fn push_missing_locked_build_identity(label: &str, build: &crate::package::LockedBuildInfo, violations: &mut Vec<String>) {
    if build.compatibility_profile_hash.is_empty() {
        violations.push(format!("{} has no compatibility_profile_hash", label));
    }
    if build.compiler_version.is_none() {
        violations.push(format!("{} has no compiler_version", label));
    }
    if build.target_profile.is_none() {
        violations.push(format!("{} has no target_profile", label));
    }
    if build.artifact_hash.is_none() {
        violations.push(format!("{} has no artifact_hash", label));
    }
    if build.metadata_hash.is_none() {
        violations.push(format!("{} has no metadata_hash", label));
    }
    if build.schema_hash.is_none() {
        violations.push(format!("{} has no schema_hash", label));
    }
    if build.cell_data_codec_manifest_hash.is_none() {
        violations.push(format!("{} has no cell_data_codec_manifest_hash", label));
    }
    if build.abi_hash.is_none() {
        violations.push(format!("{} has no abi_hash", label));
    }
    if build.constraints_hash.is_none() {
        violations.push(format!("{} has no constraints_hash", label));
    }
}

fn push_missing_deployed_build_identity(label: &str, build: &crate::package::DeployedBuildInfo, violations: &mut Vec<String>) {
    if build.compatibility_profile_hash.is_empty() {
        violations.push(format!("{} has no compatibility_profile_hash", label));
    }
    if build.compiler_version.is_none() {
        violations.push(format!("{} has no compiler_version", label));
    }
    if build.artifact_hash.is_none() {
        violations.push(format!("{} has no artifact_hash", label));
    }
    if build.metadata_hash.is_none() {
        violations.push(format!("{} has no metadata_hash", label));
    }
    if build.schema_hash.is_none() {
        violations.push(format!("{} has no schema_hash", label));
    }
    if build.cell_data_codec_manifest_hash.is_none() {
        violations.push(format!("{} has no cell_data_codec_manifest_hash", label));
    }
    if build.abi_hash.is_none() {
        violations.push(format!("{} has no abi_hash", label));
    }
    if build.constraints_hash.is_none() {
        violations.push(format!("{} has no constraints_hash", label));
    }
}

fn compare_optional_build_field(
    field: &str,
    lock_value: &Option<String>,
    deployed_value: &Option<String>,
    violations: &mut Vec<String>,
) {
    match (lock_value, deployed_value) {
        (Some(lock_value), Some(deployed_value)) if lock_value == deployed_value => {}
        (Some(lock_value), Some(deployed_value)) => {
            violations.push(format!("{} mismatch: Cell.lock has '{}', Deployed.toml has '{}'", field, lock_value, deployed_value))
        }
        (None, _) => violations.push(format!("Cell.lock [package.build] has no {}", field)),
        (_, None) => violations.push(format!("Deployed.toml [build] has no {}", field)),
    }
}

fn verify_live_deployments(
    deployed: &crate::package::DeployedManifest,
    rpc_url: &str,
    network_filter: Option<&str>,
    violations: &mut Vec<String>,
) -> Result<serde_json::Value> {
    let chain_info = ckb_rpc_call(rpc_url, "get_blockchain_info", serde_json::json!([]))?;
    let chain = chain_info.get("chain").or_else(|| chain_info.get("chain_id")).and_then(|value| value.as_str()).map(str::to_string);
    let mut evidence = Vec::new();
    let mut checked = 0usize;

    for deployment in &deployed.deployments {
        if network_filter.is_some_and(|network| network != deployment.network) {
            continue;
        }
        checked += 1;
        let mut deployment_violations = Vec::new();
        if let Some(violation) = deployment_status_violation(deployment) {
            deployment_violations.push(violation);
        }

        match chain.as_deref() {
            Some(chain) if chain_id_matches(chain, &deployment.chain_id) => {}
            Some(chain) => deployment_violations.push(format!(
                "chain_id mismatch for network '{}': RPC has '{}', Deployed.toml has '{}'",
                deployment.network, chain, deployment.chain_id
            )),
            None => deployment_violations.push("RPC get_blockchain_info did not return chain".to_string()),
        }

        let out_point = serde_json::json!({
            "tx_hash": deployment.tx_hash,
            "index": format!("0x{:x}", deployment.output_index),
        });
        let live = ckb_rpc_call(rpc_url, "get_live_cell", serde_json::json!([out_point, true]))?;
        let rpc_status = live.get("status").and_then(|value| value.as_str()).unwrap_or("unknown").to_string();
        if rpc_status != "live" {
            deployment_violations.push(format!(
                "deployment for network '{}' is not live at {}: RPC status '{}'",
                deployment.network, deployment.out_point, rpc_status
            ));
        }

        let rpc_data_hash = live_cell_data_hash(&live);
        match rpc_data_hash.as_deref() {
            Some(hash) if hex_eq(hash, &deployment.data_hash) => {}
            Some(hash) => deployment_violations.push(format!(
                "live data_hash mismatch for network '{}': RPC has '{}', Deployed.toml has '{}'",
                deployment.network, hash, deployment.data_hash
            )),
            None => deployment_violations
                .push(format!("RPC get_live_cell for network '{}' did not return cell.data.hash", deployment.network)),
        }

        let rpc_code_hash =
            live_cell_code_hash_for_deployment(&live, deployment, rpc_data_hash.as_deref(), &mut deployment_violations);
        if let Some(hash) = rpc_code_hash.as_deref()
            && !hex_eq(hash, &deployment.code_hash)
        {
            deployment_violations.push(format!(
                "live code_hash mismatch for network '{}': RPC has '{}', Deployed.toml has '{}'",
                deployment.network, hash, deployment.code_hash
            ));
        }

        if let Some(type_id) = &deployment.type_id {
            let rpc_type_args = live_cell_type_script(&live).and_then(|script| script.get("args")).and_then(|value| value.as_str());
            match rpc_type_args {
                Some(args) if hex_eq(args, type_id) => {}
                Some(args) => deployment_violations.push(format!(
                    "type_id mismatch for network '{}': RPC type args '{}', Deployed.toml has '{}'",
                    deployment.network, args, type_id
                )),
                None => deployment_violations.push(format!(
                    "deployment for network '{}' declares type_id but live cell has no type script args",
                    deployment.network
                )),
            }
        }

        for violation in &deployment_violations {
            if !violations.contains(violation) {
                violations.push(violation.clone());
            }
        }
        evidence.push(serde_json::json!({
            "network": deployment.network,
            "chain_id": deployment.chain_id,
            "deployment_status": deployment.status.as_ref(),
            "out_point": deployment.out_point,
            "rpc_status": rpc_status,
            "status": if deployment_violations.is_empty() { "live-verified" } else { "failed" },
            "expected_data_hash": deployment.data_hash,
            "rpc_data_hash": rpc_data_hash,
            "expected_code_hash": deployment.code_hash,
            "rpc_code_hash": rpc_code_hash,
            "hash_type": deployment.hash_type,
            "violations": deployment_violations,
        }));
    }

    if checked == 0 {
        violations.push(match network_filter {
            Some(network) => format!("no deployment record found for requested live network '{}'", network),
            None => "no deployment records found for live verification".to_string(),
        });
    }

    Ok(serde_json::json!({
        "enabled": true,
        "rpc_url": rpc_url,
        "network": network_filter,
        "chain": chain,
        "checked": checked,
        "evidence": evidence,
    }))
}

fn live_cell_data_hash(live: &serde_json::Value) -> Option<String> {
    live.pointer("/cell/data/hash").or_else(|| live.pointer("/cell/data_hash")).and_then(|value| value.as_str()).map(str::to_string)
}

fn live_cell_type_script(live: &serde_json::Value) -> Option<&serde_json::Value> {
    let script = live.pointer("/cell/output/type")?;
    (!script.is_null()).then_some(script)
}

fn live_cell_code_hash_for_deployment(
    live: &serde_json::Value,
    deployment: &crate::package::DeploymentRecord,
    rpc_data_hash: Option<&str>,
    violations: &mut Vec<String>,
) -> Option<String> {
    match normalize_hash_type(&deployment.hash_type).as_deref() {
        Some("data" | "data1" | "data2") => rpc_data_hash.map(str::to_string),
        Some("type") => {
            let Some(script) = live_cell_type_script(live) else {
                violations.push(format!(
                    "deployment for network '{}' uses hash_type 'type' but live cell has no type script",
                    deployment.network
                ));
                return None;
            };
            match ckb_script_hash_from_json(script) {
                Ok(hash) => Some(hash),
                Err(error) => {
                    violations
                        .push(format!("failed to compute live type script hash for network '{}': {}", deployment.network, error));
                    None
                }
            }
        }
        Some(other) => {
            violations.push(format!("unsupported deployment hash_type '{}' for live verification", other));
            None
        }
        None => {
            violations.push("deployment hash_type is empty".to_string());
            None
        }
    }
}

pub(super) fn ckb_script_hash_from_json(script: &serde_json::Value) -> Result<String> {
    let code_hash = script
        .get("code_hash")
        .and_then(|value| value.as_str())
        .ok_or_else(|| crate::error::CompileError::without_span("script has no code_hash"))?;
    let hash_type = script
        .get("hash_type")
        .and_then(|value| value.as_str())
        .ok_or_else(|| crate::error::CompileError::without_span("script has no hash_type"))?;
    let args = script.get("args").and_then(|value| value.as_str()).unwrap_or("0x");

    let code_hash_bytes = hex::decode(code_hash.trim_start_matches("0x"))
        .map_err(|error| crate::error::CompileError::without_span(format!("invalid script code_hash: {}", error)))?;
    if code_hash_bytes.len() != 32 {
        return Err(crate::error::CompileError::without_span(format!(
            "script code_hash must be 32 bytes, got {}",
            code_hash_bytes.len()
        )));
    }
    let hash_type_byte = ckb_hash_type_byte(hash_type)
        .ok_or_else(|| crate::error::CompileError::without_span(format!("unsupported script hash_type '{}'", hash_type)))?;
    let args_bytes = hex::decode(args.trim_start_matches("0x"))
        .map_err(|error| crate::error::CompileError::without_span(format!("invalid script args: {}", error)))?;

    let mut args_molecule = Vec::with_capacity(4 + args_bytes.len());
    args_molecule.extend_from_slice(&(args_bytes.len() as u32).to_le_bytes());
    args_molecule.extend_from_slice(&args_bytes);

    let header_size = 4 + 4 * 3;
    let field_sizes = [32usize, 1usize, args_molecule.len()];
    let mut cursor = header_size;
    let mut offsets = Vec::with_capacity(3);
    for size in field_sizes {
        offsets.push(cursor);
        cursor += size;
    }

    let mut serialized = Vec::with_capacity(cursor);
    serialized.extend_from_slice(&(cursor as u32).to_le_bytes());
    for offset in offsets {
        serialized.extend_from_slice(&(offset as u32).to_le_bytes());
    }
    serialized.extend_from_slice(&code_hash_bytes);
    serialized.push(hash_type_byte);
    serialized.extend_from_slice(&args_molecule);

    Ok(format!("0x{}", crate::hex_encode(&crate::ckb_blake2b256(&serialized))))
}

fn ckb_rpc_call(rpc_url: &str, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
    let endpoint = parse_http_rpc_url(rpc_url)?;
    let body = serde_json::to_string(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    }))
    .map_err(|error| crate::error::CompileError::without_span(format!("failed to serialize JSON-RPC request: {}", error)))?;

    let mut stream = TcpStream::connect((endpoint.host.as_str(), endpoint.port))
        .map_err(|error| crate::error::CompileError::without_span(format!("failed to connect to CKB RPC '{}': {}", rpc_url, error)))?;
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(10))).ok();
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        endpoint.path,
        endpoint.host_header,
        body.len(),
        body
    );
    stream.write_all(request.as_bytes()).map_err(|error| {
        crate::error::CompileError::without_span(format!("failed to write CKB RPC request '{}': {}", method, error))
    })?;

    let mut response = String::new();
    stream.read_to_string(&mut response).map_err(|error| {
        crate::error::CompileError::without_span(format!("failed to read CKB RPC response '{}': {}", method, error))
    })?;
    let Some((headers, body)) = response.split_once("\r\n\r\n") else {
        return Err(crate::error::CompileError::without_span("CKB RPC returned malformed HTTP response"));
    };
    let status_line = headers.lines().next().unwrap_or_default();
    if !status_line.contains(" 200 ") {
        return Err(crate::error::CompileError::without_span(format!("CKB RPC '{}' returned HTTP status '{}'", method, status_line)));
    }
    let value: serde_json::Value = serde_json::from_str(body).map_err(|error| {
        crate::error::CompileError::without_span(format!("failed to parse CKB RPC response '{}': {}", method, error))
    })?;
    if let Some(error) = value.get("error") {
        return Err(crate::error::CompileError::without_span(format!("CKB RPC '{}' failed: {}", method, error)));
    }
    value
        .get("result")
        .cloned()
        .ok_or_else(|| crate::error::CompileError::without_span(format!("CKB RPC '{}' returned no result", method)))
}

struct HttpRpcEndpoint {
    host: String,
    host_header: String,
    port: u16,
    path: String,
}

fn parse_http_rpc_url(url: &str) -> Result<HttpRpcEndpoint> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| crate::error::CompileError::without_span("only http:// CKB RPC URLs are supported"))?;
    let (host_port, path) = rest.split_once('/').map_or((rest, "/"), |(host_port, path)| (host_port, path));
    let path = if path == "/" { "/".to_string() } else { format!("/{path}") };
    let (host, port) = if let Some((host, port)) = host_port.rsplit_once(':') {
        let port = port
            .parse::<u16>()
            .map_err(|error| crate::error::CompileError::without_span(format!("invalid CKB RPC port '{}': {}", port, error)))?;
        (host.to_string(), port)
    } else {
        (host_port.to_string(), 80)
    };
    if host.is_empty() {
        return Err(crate::error::CompileError::without_span("CKB RPC host is empty"));
    }
    Ok(HttpRpcEndpoint { host, host_header: host_port.to_string(), port, path })
}

fn chain_id_matches(rpc_chain: &str, expected: &str) -> bool {
    let rpc = normalize_chain_id(rpc_chain);
    let expected = normalize_chain_id(expected);
    rpc == expected || (rpc == "ckb" && expected == "ckb-mainnet") || (rpc == "ckb-mainnet" && expected == "ckb")
}

fn normalize_chain_id(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace('_', "-")
}

fn hex_eq(left: &str, right: &str) -> bool {
    left.trim_start_matches("0x").eq_ignore_ascii_case(right.trim_start_matches("0x"))
}

fn normalize_hash_type(value: &str) -> Option<String> {
    let value = value.trim().to_ascii_lowercase();
    (!value.is_empty()).then_some(value)
}

fn ckb_hash_type_byte(value: &str) -> Option<u8> {
    match normalize_hash_type(value)?.as_str() {
        "data" => Some(0),
        "type" => Some(1),
        "data1" => Some(2),
        "data2" => Some(4),
        _ => None,
    }
}

fn validate_build_entry_selection(args: &BuildArgs) -> Result<()> {
    let selected = [args.artifact.is_some(), args.entry_action.is_some(), args.entry_lock.is_some()];
    if selected.into_iter().filter(|selected| *selected).count() > 1 {
        return Err(crate::error::CompileError::without_span("--artifact, --entry-action, and --entry-lock are mutually exclusive"));
    }
    Ok(())
}

fn effective_build_check_args(args: &BuildArgs) -> Result<CheckArgs> {
    effective_check_args(CheckArgs {
        all_targets: false,
        artifact: args.artifact.clone(),
        target_profile: args.target_profile.clone(),
        features: args.features.clone(),
        all_features: args.all_features,
        no_default_features: args.no_default_features,
        locked: args.locked,
        frozen: args.frozen,
        offline: args.offline,
        environment: args.environment.clone(),
        json: false,
        production: args.production,
        deny_fail_closed: args.deny_fail_closed,
        deny_ckb_runtime: args.deny_ckb_runtime,
        deny_runtime_obligations: args.deny_runtime_obligations,
        primitive_compat: args.primitive_compat.clone(),
        package: None,
        workspace: false,
    })
}

fn merge_check_policy(args: &mut CheckArgs, policy: &PolicyConfig) {
    args.production |= policy.production;
    args.deny_fail_closed |= policy.deny_fail_closed;
    args.deny_ckb_runtime |= policy.deny_ckb_runtime;
    args.deny_runtime_obligations |= policy.deny_runtime_obligations;
}

fn validate_expected_metadata_hash(field: &str, actual: Option<&str>, expected: Option<&str>) -> Result<()> {
    let Some(expected) = expected else {
        return Ok(());
    };
    if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
        return Err(crate::error::CompileError::without_span(format!(
            "{} expectation must be a 64-character lowercase CKB Blake2b hex digest, got '{}'",
            field, expected
        )));
    }
    match actual {
        Some(actual) if actual.eq_ignore_ascii_case(expected) => Ok(()),
        Some(actual) => Err(crate::error::CompileError::without_span(format!(
            "metadata {} '{}' does not match expected '{}'",
            field, actual, expected
        ))),
        None => Err(crate::error::CompileError::without_span(format!(
            "metadata is missing {} required by expectation '{}'",
            field, expected
        ))),
    }
}

fn validate_expected_target_profile(actual: &str, expected: Option<&str>) -> Result<()> {
    let Some(expected) = expected else {
        return Ok(());
    };
    let expected_profile = TargetProfile::from_name(expected)?;
    if actual == expected_profile.name() {
        return Ok(());
    }

    Err(crate::error::CompileError::without_span(format!(
        "metadata target_profile '{}' does not match expected '{}'",
        actual,
        expected_profile.name()
    )))
}

fn validate_check_policy(metadata: &crate::CompileMetadata, args: &CheckArgs) -> Result<()> {
    let mut violations = Vec::new();

    if args.primitive_compat.as_deref() == Some("0.16") {
        if let Err(error) = crate::proof_plan::soundness::validate_metadata(metadata, true) {
            violations.push(error.into_message());
        }
    } else if matches!(args.primitive_compat.as_deref(), Some("0.17" | "0.18")) {
        if let Err(error) = crate::validate_primitive_strict_017_metadata(metadata) {
            violations.push(error.into_message());
        }
    } else if metadata.runtime.proof_plan_soundness.status == "failed" {
        violations.push(format!("ProofPlan soundness failed: {} issue(s)", metadata.runtime.proof_plan_soundness.issue_count));
    }

    if args.production || args.deny_fail_closed {
        if !metadata.constraints.failures.is_empty() {
            violations.push(format!("constraints failures: {}", metadata.constraints.failures.join(", ")));
        }

        if !metadata.runtime.fail_closed_runtime_features.is_empty() {
            violations.push(format!("fail-closed runtime features: {}", metadata.runtime.fail_closed_runtime_features.join(", ")));
        }

        let fail_closed_obligations = metadata
            .runtime
            .verifier_obligations
            .iter()
            .filter(|obligation| obligation.status == "fail-closed")
            .map(|obligation| format!("{}:{} ({})", obligation.scope, obligation.feature, obligation.category))
            .collect::<Vec<_>>();
        if !fail_closed_obligations.is_empty() {
            violations.push(format!("fail-closed verifier obligations: {}", fail_closed_obligations.join(", ")));
        }
    }

    if args.production {
        let blocking_consensus_gaps = metadata
            .runtime
            .proof_plan
            .iter()
            .filter(|plan| crate::proof_plan_has_blocking_consensus_gap(plan))
            .map(|plan| format!("{}:{} ({})", plan.origin, plan.feature, plan.codegen_coverage_status))
            .collect::<Vec<_>>();
        if !blocking_consensus_gaps.is_empty() {
            violations.push(format!(
                "unresolved consensus ProofPlan gaps cannot support production artifacts: {}",
                blocking_consensus_gaps.join(", ")
            ));
        }
    }

    if args.deny_ckb_runtime && metadata.runtime.ckb_runtime_required {
        violations.push(format!("CKB runtime features: {}", metadata.runtime.ckb_runtime_features.join(", ")));
    }

    if args.deny_runtime_obligations {
        let runtime_required_obligations = metadata
            .runtime
            .verifier_obligations
            .iter()
            .filter(|obligation| obligation.status == "runtime-required")
            .map(|obligation| format!("{}:{} ({})", obligation.scope, obligation.feature, obligation.category))
            .collect::<Vec<_>>();
        if !runtime_required_obligations.is_empty() {
            violations.push(format!("runtime-required verifier obligations: {}", runtime_required_obligations.join(", ")));
        }

        let runtime_required_proof_plan = metadata
            .runtime
            .proof_plan
            .iter()
            .filter(|plan| plan.status == "runtime-required" && !plan.on_chain_checked)
            .map(|plan| format!("{}:{} ({})", plan.origin, plan.feature, plan.codegen_coverage_status))
            .collect::<Vec<_>>();
        if !runtime_required_proof_plan.is_empty() {
            violations.push(format!("runtime-required ProofPlan gaps: {}", runtime_required_proof_plan.join(", ")));
        }

        let transaction_invariants = transaction_invariant_checked_subcondition_summaries(metadata);
        if !transaction_invariants.is_empty() {
            violations.push(format!(
                "runtime-required transaction invariants with checked subconditions: {}",
                transaction_invariants.join(", ")
            ));
        }

        let transaction_runtime_inputs = transaction_runtime_input_requirement_summaries_by_status(metadata, "runtime-required");
        if !transaction_runtime_inputs.is_empty() {
            violations
                .push(format!("runtime-required transaction runtime input requirements: {}", transaction_runtime_inputs.join(", ")));
        }

        let transaction_runtime_input_blockers = transaction_runtime_input_blocker_summaries_by_status(metadata, "runtime-required");
        if !transaction_runtime_input_blockers.is_empty() {
            violations.push(format!(
                "runtime-required transaction runtime input blockers: {}",
                transaction_runtime_input_blockers.join(", ")
            ));
        }

        let transaction_runtime_input_blocker_classes =
            transaction_runtime_input_blocker_class_summaries_by_status(metadata, "runtime-required");
        if !transaction_runtime_input_blocker_classes.is_empty() {
            violations.push(format!(
                "runtime-required transaction runtime input blocker classes: {}",
                transaction_runtime_input_blocker_classes.join(", ")
            ));
        }

        let runtime_required_pool_invariants = pool_invariant_family_summaries(metadata, "runtime-required");
        if !runtime_required_pool_invariants.is_empty() {
            violations.push(format!("runtime-required Pool invariant families: {}", runtime_required_pool_invariants.join(", ")));
        }

        let runtime_required_pool_blocker_classes = pool_invariant_family_blocker_class_summaries(metadata, "runtime-required");
        if !runtime_required_pool_blocker_classes.is_empty() {
            violations.push(format!(
                "runtime-required Pool invariant blocker classes: {}",
                runtime_required_pool_blocker_classes.join(", ")
            ));
        }

        let pool_runtime_inputs = pool_runtime_input_requirement_summaries(metadata);
        if !pool_runtime_inputs.is_empty() {
            violations.push(format!("runtime-required Pool runtime input requirements: {}", pool_runtime_inputs.join(", ")));
        }
    }

    if violations.is_empty() {
        return Ok(());
    }

    Err(crate::error::CompileError::without_span(format!("check policy failed:\n  - {}", violations.join("\n  - "))))
}

fn executable_surface_policy(args: &CheckArgs) -> ExecutableSurfacePolicy {
    if args.production || args.deny_fail_closed {
        ExecutableSurfacePolicy::DenyFailClosed
    } else {
        ExecutableSurfacePolicy::AllowFailClosed
    }
}

fn target_profile_policy_violations(
    metadata: &crate::CompileMetadata,
    artifact_format: ArtifactFormat,
    profile: TargetProfile,
) -> Vec<String> {
    match profile {
        TargetProfile::Ckb => ckb_target_profile_policy_violations(metadata, artifact_format),
    }
}

fn ckb_target_profile_policy_violations(_metadata: &crate::CompileMetadata, _artifact_format: ArtifactFormat) -> Vec<String> {
    Vec::new()
}

fn runtime_required_obligation_count(metadata: &crate::CompileMetadata) -> usize {
    metadata.runtime.verifier_obligations.iter().filter(|obligation| obligation.status == "runtime-required").count()
}

fn fail_closed_obligation_count(metadata: &crate::CompileMetadata) -> usize {
    metadata.runtime.verifier_obligations.iter().filter(|obligation| obligation.status == "fail-closed").count()
}

fn runtime_required_transaction_invariant_count(metadata: &crate::CompileMetadata) -> usize {
    metadata
        .runtime
        .verifier_obligations
        .iter()
        .filter(|obligation| obligation.category == "transaction-invariant" && obligation.status == "runtime-required")
        .count()
}

fn runtime_required_transaction_invariant_checked_subcondition_count(metadata: &crate::CompileMetadata) -> usize {
    metadata
        .runtime
        .verifier_obligations
        .iter()
        .filter(|obligation| obligation.category == "transaction-invariant" && obligation.status == "runtime-required")
        .map(|obligation| checked_runtime_subconditions(&obligation.detail).len())
        .sum()
}

fn transaction_invariant_checked_subcondition_summaries(metadata: &crate::CompileMetadata) -> Vec<String> {
    metadata
        .runtime
        .verifier_obligations
        .iter()
        .filter(|obligation| obligation.category == "transaction-invariant" && obligation.status == "runtime-required")
        .filter_map(|obligation| {
            let subconditions = checked_runtime_subconditions(&obligation.detail);
            if subconditions.is_empty() {
                None
            } else {
                Some(format!("{}:{} checked=[{}]", obligation.scope, obligation.feature, subconditions.join(",")))
            }
        })
        .collect()
}

fn transaction_runtime_input_requirement_count(metadata: &crate::CompileMetadata) -> usize {
    metadata.runtime.transaction_runtime_input_requirements.len()
}

fn transaction_runtime_input_requirement_count_by_status(metadata: &crate::CompileMetadata, status: &str) -> usize {
    metadata.runtime.transaction_runtime_input_requirements.iter().filter(|requirement| requirement.status == status).count()
}

fn transaction_runtime_input_requirement_summaries(metadata: &crate::CompileMetadata) -> Vec<String> {
    metadata.runtime.transaction_runtime_input_requirements.iter().map(transaction_runtime_input_requirement_summary).collect()
}

fn transaction_runtime_input_requirement_summaries_by_status(metadata: &crate::CompileMetadata, status: &str) -> Vec<String> {
    metadata
        .runtime
        .transaction_runtime_input_requirements
        .iter()
        .filter(|requirement| requirement.status == status)
        .map(transaction_runtime_input_requirement_summary)
        .collect()
}

fn transaction_runtime_input_blocker_count_by_status(metadata: &crate::CompileMetadata, status: &str) -> usize {
    transaction_runtime_input_blocker_summaries_by_status(metadata, status).len()
}

fn transaction_runtime_input_blocker_summaries_by_status(metadata: &crate::CompileMetadata, status: &str) -> Vec<String> {
    metadata
        .runtime
        .transaction_runtime_input_requirements
        .iter()
        .filter(|requirement| requirement.status == status)
        .filter_map(|requirement| {
            requirement.blocker.as_deref().map(|blocker| {
                let blocker_class = requirement
                    .blocker_class
                    .as_deref()
                    .map(|blocker_class| format!(" blocker_class={}", blocker_class))
                    .unwrap_or_default();
                format!("{}:{}:{} blocker={}{}", requirement.scope, requirement.feature, requirement.component, blocker, blocker_class)
            })
        })
        .collect()
}

fn transaction_runtime_input_blocker_class_count_by_status(metadata: &crate::CompileMetadata, status: &str) -> usize {
    transaction_runtime_input_blocker_class_summaries_by_status(metadata, status).len()
}

fn transaction_runtime_input_blocker_class_summaries_by_status(metadata: &crate::CompileMetadata, status: &str) -> Vec<String> {
    metadata
        .runtime
        .transaction_runtime_input_requirements
        .iter()
        .filter(|requirement| requirement.status == status)
        .filter_map(|requirement| {
            requirement.blocker_class.as_deref().map(|blocker_class| {
                format!("{}:{}:{} blocker_class={}", requirement.scope, requirement.feature, requirement.component, blocker_class)
            })
        })
        .collect()
}

fn transaction_runtime_input_requirement_summary(requirement: &crate::TransactionRuntimeInputRequirementMetadata) -> String {
    let field = requirement.field.as_deref().map(|field| format!(".{}", field)).unwrap_or_default();
    let bytes = requirement.byte_len.map(|byte_len| format!("[{}]", byte_len)).unwrap_or_default();
    let blocker = requirement.blocker.as_deref().map(|blocker| format!(" blocker={}", blocker)).unwrap_or_default();
    let blocker_class = requirement.blocker_class.as_deref().map(|class| format!(" blocker_class={}", class)).unwrap_or_default();
    format!(
        "{}:{}:{}={}:{}{}:{}{} ({}){}{}",
        requirement.scope,
        requirement.feature,
        requirement.component,
        requirement.source,
        requirement.binding,
        field,
        requirement.abi,
        bytes,
        requirement.status,
        blocker,
        blocker_class
    )
}

fn checked_runtime_subconditions(detail: &str) -> Vec<String> {
    detail
        .split(|ch: char| ch == ',' || ch == ';' || ch.is_whitespace())
        .filter_map(|part| part.trim().strip_suffix("=checked-runtime"))
        .map(|name| name.trim_matches(|ch: char| ch == '`' || ch == '.' || ch == ':').to_string())
        .filter(|name| !name.is_empty())
        .collect()
}

fn checked_pool_invariant_family_count(metadata: &crate::CompileMetadata) -> usize {
    pool_invariant_family_summaries(metadata, "checked-runtime").len()
}

fn runtime_required_pool_invariant_family_count(metadata: &crate::CompileMetadata) -> usize {
    pool_invariant_family_summaries(metadata, "runtime-required").len()
}

fn pool_runtime_input_requirement_count(metadata: &crate::CompileMetadata) -> usize {
    metadata.runtime.pool_primitives.iter().map(|primitive| primitive.runtime_input_requirements.len()).sum()
}

fn pool_runtime_input_requirement_summaries(metadata: &crate::CompileMetadata) -> Vec<String> {
    metadata
        .runtime
        .pool_primitives
        .iter()
        .flat_map(|primitive| {
            primitive.runtime_input_requirements.iter().map(move |requirement| {
                let field = requirement.field.as_deref().map(|field| format!(".{}", field)).unwrap_or_default();
                let blocker = requirement.blocker.as_deref().map(|blocker| format!(" blocker={}", blocker)).unwrap_or_default();
                let blocker_class =
                    requirement.blocker_class.as_deref().map(|class| format!(" blocker_class={}", class)).unwrap_or_default();
                format!(
                    "{}:{}:{}={}#{}:{}{}:{}[{}]{}{}",
                    primitive.scope,
                    primitive.feature,
                    requirement.component,
                    requirement.source,
                    requirement.index,
                    requirement.binding,
                    field,
                    requirement.abi,
                    requirement.byte_len,
                    blocker,
                    blocker_class
                )
            })
        })
        .collect()
}

fn pool_invariant_family_summaries(metadata: &crate::CompileMetadata, status: &str) -> Vec<String> {
    metadata
        .runtime
        .pool_primitives
        .iter()
        .flat_map(|primitive| {
            primitive.invariant_families.iter().filter(move |family| family.status == status).map(move |family| {
                let blocker = family.blocker.as_deref().map(|blocker| format!(" blocker={}", blocker)).unwrap_or_default();
                let blocker_class =
                    family.blocker_class.as_deref().map(|class| format!(" blocker_class={}", class)).unwrap_or_default();
                format!("{}:{}:{} ({}){}{}", primitive.scope, primitive.feature, family.name, family.source, blocker, blocker_class)
            })
        })
        .collect()
}

fn pool_invariant_family_blocker_class_count(metadata: &crate::CompileMetadata, status: &str) -> usize {
    pool_invariant_family_blocker_class_summaries(metadata, status).len()
}

fn pool_invariant_family_blocker_class_summaries(metadata: &crate::CompileMetadata, status: &str) -> Vec<String> {
    metadata
        .runtime
        .pool_primitives
        .iter()
        .flat_map(|primitive| {
            primitive.invariant_families.iter().filter(move |family| family.status == status).filter_map(move |family| {
                family.blocker_class.as_deref().map(|blocker_class| {
                    format!("{}:{}:{} blocker_class={}", primitive.scope, primitive.feature, family.name, blocker_class)
                })
            })
        })
        .collect()
}

#[derive(Debug, Default)]
struct CompileTestExpectation {
    expect_success: bool,
    expect_fail: bool,
    expected_errors: Vec<String>,
    target: Option<String>,
    production: bool,
    deny_fail_closed: bool,
    deny_ckb_runtime: bool,
    deny_runtime_obligations: bool,
    expect_standalone: Option<bool>,
    expect_ckb_runtime: Option<bool>,
    expect_fail_closed: Option<bool>,
    expected_runtime_features: Vec<String>,
    forbidden_runtime_features: Vec<String>,
    expected_verifier_obligations: Vec<String>,
    forbidden_verifier_obligations: Vec<String>,
    expected_runtime_required_obligations: Vec<String>,
    forbidden_runtime_required_obligations: Vec<String>,
    expected_artifact_format: Option<String>,
    expected_actions: Vec<String>,
    forbidden_actions: Vec<String>,
    expected_functions: Vec<String>,
    forbidden_functions: Vec<String>,
    expected_locks: Vec<String>,
    forbidden_locks: Vec<String>,
}

impl CompileTestExpectation {
    fn check_args(&self) -> CheckArgs {
        CheckArgs {
            all_targets: false,
            artifact: None,
            target_profile: None,
            features: Vec::new(),
            all_features: false,
            no_default_features: false,
            locked: true,
            frozen: false,
            offline: false,
            environment: None,
            json: false,
            production: self.production,
            deny_fail_closed: self.deny_fail_closed,
            deny_ckb_runtime: self.deny_ckb_runtime,
            deny_runtime_obligations: self.deny_runtime_obligations,
            primitive_compat: None,
            package: None,
            workspace: false,
        }
    }
}

fn read_test_expectation(path: &Path) -> Result<CompileTestExpectation> {
    let source = std::fs::read_to_string(path)
        .map_err(|error| crate::error::CompileError::without_span(format!("failed to read test '{}': {}", path.display(), error)))?;
    parse_test_expectation(path, &source)
}

fn parse_test_expectation(path: &Path, source: &str) -> Result<CompileTestExpectation> {
    let mut expectation = CompileTestExpectation::default();
    for (line_number, line) in source.lines().enumerate() {
        let Some(marker) = line.split("//").nth(1).map(str::trim) else {
            continue;
        };
        let Some(directive) = marker.strip_prefix("cellscript-test:").map(str::trim) else {
            continue;
        };

        if directive == "expect-success" {
            expectation.expect_success = true;
        } else if directive == "expect-fail" {
            expectation.expect_fail = true;
        } else if let Some(expected) = directive.strip_prefix("expect-error:").map(str::trim) {
            expectation.expect_fail = true;
            if !expected.is_empty() {
                expectation.expected_errors.push(expected.to_string());
            }
        } else if let Some(target) = directive.strip_prefix("target:").map(str::trim) {
            if target.is_empty() {
                return Err(compile_test_directive_error(path, line_number, "target directive requires a non-empty target"));
            }
            if expectation.target.replace(target.to_string()).is_some() {
                return Err(compile_test_directive_error(path, line_number, "target directive may only appear once"));
            }
        } else if directive == "production" {
            expectation.production = true;
        } else if directive == "deny-fail-closed" {
            expectation.deny_fail_closed = true;
        } else if directive == "deny-ckb-runtime" {
            expectation.deny_ckb_runtime = true;
        } else if directive == "deny-runtime-obligations" {
            expectation.deny_runtime_obligations = true;
        } else if directive == "expect-standalone" {
            expectation.expect_standalone = Some(true);
        } else if directive == "expect-not-standalone" {
            expectation.expect_standalone = Some(false);
        } else if directive == "expect-ckb-runtime" {
            expectation.expect_ckb_runtime = Some(true);
        } else if directive == "expect-no-ckb-runtime" {
            expectation.expect_ckb_runtime = Some(false);
        } else if directive == "expect-fail-closed-runtime" {
            expectation.expect_fail_closed = Some(true);
        } else if directive == "expect-no-fail-closed-runtime" {
            expectation.expect_fail_closed = Some(false);
        } else if let Some(feature) = directive.strip_prefix("expect-runtime-feature:").map(str::trim) {
            if feature.is_empty() {
                return Err(compile_test_directive_error(path, line_number, "expect-runtime-feature requires non-empty text"));
            }
            expectation.expected_runtime_features.push(feature.to_string());
        } else if let Some(feature) = directive.strip_prefix("expect-no-runtime-feature:").map(str::trim) {
            if feature.is_empty() {
                return Err(compile_test_directive_error(path, line_number, "expect-no-runtime-feature requires non-empty text"));
            }
            expectation.forbidden_runtime_features.push(feature.to_string());
        } else if let Some(obligation) = directive.strip_prefix("expect-verifier-obligation:").map(str::trim) {
            push_non_empty_test_directive(
                path,
                line_number,
                "expect-verifier-obligation",
                obligation,
                &mut expectation.expected_verifier_obligations,
            )?;
        } else if let Some(obligation) = directive.strip_prefix("expect-no-verifier-obligation:").map(str::trim) {
            push_non_empty_test_directive(
                path,
                line_number,
                "expect-no-verifier-obligation",
                obligation,
                &mut expectation.forbidden_verifier_obligations,
            )?;
        } else if let Some(obligation) = directive.strip_prefix("expect-runtime-required-obligation:").map(str::trim) {
            push_non_empty_test_directive(
                path,
                line_number,
                "expect-runtime-required-obligation",
                obligation,
                &mut expectation.expected_runtime_required_obligations,
            )?;
        } else if let Some(obligation) = directive.strip_prefix("expect-no-runtime-required-obligation:").map(str::trim) {
            push_non_empty_test_directive(
                path,
                line_number,
                "expect-no-runtime-required-obligation",
                obligation,
                &mut expectation.forbidden_runtime_required_obligations,
            )?;
        } else if let Some(format) = directive.strip_prefix("expect-artifact-format:").map(str::trim) {
            if format.is_empty() {
                return Err(compile_test_directive_error(path, line_number, "expect-artifact-format requires non-empty text"));
            }
            if expectation.expected_artifact_format.replace(format.to_string()).is_some() {
                return Err(compile_test_directive_error(path, line_number, "expect-artifact-format may only appear once"));
            }
        } else if let Some(name) = directive.strip_prefix("expect-action:").map(str::trim) {
            push_non_empty_test_directive(path, line_number, "expect-action", name, &mut expectation.expected_actions)?;
        } else if let Some(name) = directive.strip_prefix("expect-no-action:").map(str::trim) {
            push_non_empty_test_directive(path, line_number, "expect-no-action", name, &mut expectation.forbidden_actions)?;
        } else if let Some(name) = directive.strip_prefix("expect-function:").map(str::trim) {
            push_non_empty_test_directive(path, line_number, "expect-function", name, &mut expectation.expected_functions)?;
        } else if let Some(name) = directive.strip_prefix("expect-no-function:").map(str::trim) {
            push_non_empty_test_directive(path, line_number, "expect-no-function", name, &mut expectation.forbidden_functions)?;
        } else if let Some(name) = directive.strip_prefix("expect-lock:").map(str::trim) {
            push_non_empty_test_directive(path, line_number, "expect-lock", name, &mut expectation.expected_locks)?;
        } else if let Some(name) = directive.strip_prefix("expect-no-lock:").map(str::trim) {
            push_non_empty_test_directive(path, line_number, "expect-no-lock", name, &mut expectation.forbidden_locks)?;
        } else {
            return Err(compile_test_directive_error(
                path,
                line_number,
                &format!("unknown cellscript-test directive '{}'", directive),
            ));
        }
    }
    if expectation.expect_success && expectation.expect_fail {
        return Err(crate::error::CompileError::without_span(format!(
            "{}: conflicting cellscript-test directives: expect-success cannot be combined with expect-fail/expect-error",
            path.display()
        )));
    }
    Ok(expectation)
}

fn push_non_empty_test_directive(
    path: &Path,
    zero_based_line: usize,
    directive: &str,
    value: &str,
    values: &mut Vec<String>,
) -> Result<()> {
    if value.is_empty() {
        return Err(compile_test_directive_error(path, zero_based_line, &format!("{} requires non-empty text", directive)));
    }
    values.push(value.to_string());
    Ok(())
}

fn compile_test_directive_error(path: &Path, zero_based_line: usize, message: &str) -> crate::error::CompileError {
    crate::error::CompileError::without_span(format!("{}:{}: {}", path.display(), zero_based_line + 1, message))
}

fn evaluate_compile_test_result(
    path: &Utf8Path,
    expectation: &CompileTestExpectation,
    result: Result<crate::CompileResult>,
) -> Result<()> {
    match (expectation.expect_fail, result) {
        (false, Ok(result)) => validate_compile_test_metadata(path, expectation, &result.metadata),
        (false, Err(error)) => {
            Err(crate::error::CompileError::without_span(format!("{}: expected compile success, got error: {}", path, error)))
        }
        (true, Ok(_)) => Err(crate::error::CompileError::without_span(format!("{}: expected compile failure, got success", path))),
        (true, Err(error)) => {
            let message = error.to_string();
            let missing = expectation
                .expected_errors
                .iter()
                .filter(|expected| !message.contains(expected.as_str()))
                .cloned()
                .collect::<Vec<_>>();
            if missing.is_empty() {
                Ok(())
            } else {
                Err(crate::error::CompileError::without_span(format!(
                    "{}: expected error text not found: {}; actual error: {}",
                    path,
                    missing.join(", "),
                    message
                )))
            }
        }
    }
}

fn validate_compile_test_metadata(
    path: &Utf8Path,
    expectation: &CompileTestExpectation,
    metadata: &crate::CompileMetadata,
) -> Result<()> {
    if let Some(expected) = &expectation.expected_artifact_format
        && &metadata.artifact_format != expected
    {
        return Err(crate::error::CompileError::without_span(format!(
            "{}: expected artifact_format='{}', got '{}'",
            path, expected, metadata.artifact_format
        )));
    }

    if let Some(expected) = expectation.expect_standalone
        && metadata.runtime.standalone_runner_compatible != expected
    {
        return Err(crate::error::CompileError::without_span(format!(
            "{}: expected standalone_runner_compatible={}, got {}",
            path, expected, metadata.runtime.standalone_runner_compatible
        )));
    }
    if let Some(expected) = expectation.expect_ckb_runtime
        && metadata.runtime.ckb_runtime_required != expected
    {
        return Err(crate::error::CompileError::without_span(format!(
            "{}: expected ckb_runtime_required={}, got {}",
            path, expected, metadata.runtime.ckb_runtime_required
        )));
    }
    if let Some(expected) = expectation.expect_fail_closed {
        let actual = !metadata.runtime.fail_closed_runtime_features.is_empty()
            || metadata.runtime.verifier_obligations.iter().any(|obligation| obligation.status == "fail-closed");
        if actual != expected {
            return Err(crate::error::CompileError::without_span(format!(
                "{}: expected fail_closed_runtime={}, got {}",
                path, expected, actual
            )));
        }
    }

    let runtime_summary = compile_test_runtime_summary(metadata);
    for expected in &expectation.expected_runtime_features {
        if !runtime_summary.contains(expected) {
            return Err(crate::error::CompileError::without_span(format!(
                "{}: expected runtime metadata to contain '{}'",
                path, expected
            )));
        }
    }
    for forbidden in &expectation.forbidden_runtime_features {
        if runtime_summary.contains(forbidden) {
            return Err(crate::error::CompileError::without_span(format!(
                "{}: expected runtime metadata not to contain '{}'",
                path, forbidden
            )));
        }
    }

    validate_compile_test_summary_contains(
        path,
        "verifier obligation",
        &compile_test_obligation_summary(metadata, None),
        &expectation.expected_verifier_obligations,
        &expectation.forbidden_verifier_obligations,
    )?;
    validate_compile_test_summary_contains(
        path,
        "runtime-required verifier obligation",
        &compile_test_obligation_summary(metadata, Some("runtime-required")),
        &expectation.expected_runtime_required_obligations,
        &expectation.forbidden_runtime_required_obligations,
    )?;

    validate_named_metadata_set(
        path,
        "action",
        &metadata.actions.iter().map(|action| action.name.as_str()).collect::<Vec<_>>(),
        &expectation.expected_actions,
        &expectation.forbidden_actions,
    )?;
    validate_named_metadata_set(
        path,
        "function",
        &metadata.functions.iter().map(|function| function.name.as_str()).collect::<Vec<_>>(),
        &expectation.expected_functions,
        &expectation.forbidden_functions,
    )?;
    validate_named_metadata_set(
        path,
        "lock",
        &metadata.locks.iter().map(|lock| lock.name.as_str()).collect::<Vec<_>>(),
        &expectation.expected_locks,
        &expectation.forbidden_locks,
    )?;

    Ok(())
}

fn validate_compile_test_summary_contains(
    path: &Utf8Path,
    label: &str,
    summary: &str,
    expected: &[String],
    forbidden: &[String],
) -> Result<()> {
    for expected in expected {
        if !summary.contains(expected) {
            return Err(crate::error::CompileError::without_span(format!(
                "{}: expected {} metadata to contain '{}'",
                path, label, expected
            )));
        }
    }
    for forbidden in forbidden {
        if summary.contains(forbidden) {
            return Err(crate::error::CompileError::without_span(format!(
                "{}: expected {} metadata not to contain '{}'",
                path, label, forbidden
            )));
        }
    }
    Ok(())
}

fn validate_named_metadata_set(path: &Utf8Path, kind: &str, actual: &[&str], expected: &[String], forbidden: &[String]) -> Result<()> {
    for name in expected {
        if !actual.iter().any(|actual_name| actual_name == name) {
            return Err(crate::error::CompileError::without_span(format!(
                "{}: expected {} metadata to contain '{}'",
                path, kind, name
            )));
        }
    }
    for name in forbidden {
        if actual.iter().any(|actual_name| actual_name == name) {
            return Err(crate::error::CompileError::without_span(format!(
                "{}: expected {} metadata not to contain '{}'",
                path, kind, name
            )));
        }
    }
    Ok(())
}

fn compile_test_runtime_summary(metadata: &crate::CompileMetadata) -> String {
    let mut values = Vec::new();
    values.extend(metadata.runtime.ckb_runtime_features.iter().cloned());
    values.extend(metadata.runtime.fail_closed_runtime_features.iter().cloned());
    for access in &metadata.runtime.ckb_runtime_accesses {
        values.push(format!(
            "{}:{}:{}:{}:{}:{}",
            access.operation,
            access.syscall,
            access.source,
            access.index,
            access.binding,
            serde_json::to_string(&access.provenance).expect("runtime access provenance must serialize")
        ));
    }
    for obligation in &metadata.runtime.verifier_obligations {
        values.push(format!(
            "{}:{}:{}:{}:{}",
            obligation.scope, obligation.category, obligation.feature, obligation.status, obligation.detail
        ));
    }
    values.join("\n")
}

fn compile_test_obligation_summary(metadata: &crate::CompileMetadata, status: Option<&str>) -> String {
    metadata
        .runtime
        .verifier_obligations
        .iter()
        .filter(|obligation| match status {
            Some(status) => obligation.status == status,
            None => true,
        })
        .map(|obligation| {
            format!("{}:{}:{}:{}:{}", obligation.scope, obligation.category, obligation.feature, obligation.status, obligation.detail)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn collect_cell_files(root: &Path) -> Result<Vec<PathBuf>> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    if root.is_file() {
        return Ok(if root.extension().and_then(|ext| ext.to_str()) == Some("cell") { vec![root.to_path_buf()] } else { Vec::new() });
    }

    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|ext| ext.to_str()) == Some("cell") {
                files.push(path);
            }
        }
    }
    Ok(files)
}

#[cfg(feature = "vm-runner")]
fn run_elf_in_ckb_vm(program: &[u8], args: &[Vec<u8>]) -> Result<u64> {
    let core_machine =
        <<CliVmMachine as DefaultMachineRunner>::Inner as SupportMachine>::new(ISA_IMC | ISA_B | ISA_MOP, VERSION2, 10_000_000);
    let builder = DefaultMachineBuilder::new(core_machine).instruction_cycle_func(Box::new(estimate_cycles));
    let mut machine = CliVmMachine::new(builder.build());
    let program = Bytes::copy_from_slice(crate::strip_vm_abi_trailer(program));
    let args = args.iter().cloned().map(Bytes::from).map(Ok);

    machine
        .load_program(&program, args)
        .map_err(|error| crate::error::CompileError::without_span(format!("cellc run failed to load ELF: {}", error)))?;
    let exit_code =
        machine.run().map_err(|error| crate::error::CompileError::without_span(format!("cellc run VM error: {}", error)))?;
    if exit_code != 0 {
        return Err(crate::error::CompileError::without_span(format!("cellc run exited with code {}", exit_code)));
    }

    Ok(machine.machine.cycles())
}

struct SelectedEntryWitnessMetadata<'a> {
    kind: &'static str,
    name: &'a str,
    params: &'a [ParamMetadata],
    runtime_bound_param_names: std::collections::BTreeSet<String>,
}

fn select_entry_witness_metadata<'a>(
    metadata: &'a CompileMetadata,
    action: Option<&str>,
    lock: Option<&str>,
) -> Result<SelectedEntryWitnessMetadata<'a>> {
    if let Some(name) = action {
        let action = metadata
            .actions
            .iter()
            .find(|candidate| candidate.name == name)
            .ok_or_else(|| crate::error::CompileError::without_span(format!("action '{}' was not found in metadata", name)))?;
        return Ok(SelectedEntryWitnessMetadata {
            kind: "action",
            name: action.name.as_str(),
            params: &action.params,
            runtime_bound_param_names: crate::runtime_bound_param_names(&action.params),
        });
    }
    if let Some(name) = lock {
        let lock = metadata
            .locks
            .iter()
            .find(|candidate| candidate.name == name)
            .ok_or_else(|| crate::error::CompileError::without_span(format!("lock '{}' was not found in metadata", name)))?;
        return Ok(SelectedEntryWitnessMetadata {
            kind: "lock",
            name: lock.name.as_str(),
            params: &lock.params,
            runtime_bound_param_names: crate::runtime_bound_param_names(&lock.params),
        });
    }

    let mut entries = metadata
        .actions
        .iter()
        .filter(|action| !action.params.is_empty())
        .map(|action| SelectedEntryWitnessMetadata {
            kind: "action",
            name: action.name.as_str(),
            params: action.params.as_slice(),
            runtime_bound_param_names: crate::runtime_bound_param_names(&action.params),
        })
        .chain(metadata.locks.iter().filter(|lock| !lock.params.is_empty()).map(|lock| SelectedEntryWitnessMetadata {
            kind: "lock",
            name: lock.name.as_str(),
            params: lock.params.as_slice(),
            runtime_bound_param_names: crate::runtime_bound_param_names(&lock.params),
        }))
        .collect::<Vec<_>>();

    match entries.len() {
        1 => Ok(entries.remove(0)),
        0 => Err(crate::error::CompileError::without_span(
            "no parameterized action or lock found; specify --action or --lock for explicit selection",
        )),
        _ => Err(crate::error::CompileError::without_span(
            "multiple parameterized actions/locks found; specify --action NAME or --lock NAME",
        )),
    }
}

fn parse_entry_witness_arg(param: &ParamMetadata, value: &str) -> Result<EntryWitnessArg> {
    if param.schema_pointer_abi || param.schema_length_abi {
        return decode_hex_arg(&param.name, value, None).map(EntryWitnessArg::Bytes);
    }

    if let Some(width) = param.fixed_byte_len {
        return parse_entry_witness_fixed_arg(param, value, width);
    }

    match param.ty.as_str() {
        "bool" => parse_bool_arg(&param.name, value).map(EntryWitnessArg::Bool),
        "u8" => parse_integer_arg(&param.name, value, u8::MAX as u128).map(|value| EntryWitnessArg::U8(value as u8)),
        "u16" => parse_integer_arg(&param.name, value, u16::MAX as u128).map(|value| EntryWitnessArg::U16(value as u16)),
        "u32" => parse_integer_arg(&param.name, value, u32::MAX as u128).map(|value| EntryWitnessArg::U32(value as u32)),
        "u64" => parse_integer_arg(&param.name, value, u64::MAX as u128).map(|value| EntryWitnessArg::U64(value as u64)),
        temporal if crate::ir::is_ckb_temporal_scalar_name(temporal) => {
            parse_integer_arg(&param.name, value, u64::MAX as u128).map(|value| EntryWitnessArg::U64(value as u64))
        }
        "()" => Ok(EntryWitnessArg::Unit),
        other => {
            let Some(width) = crate::entry_witness_static_type_len(other).filter(|width| (1..=8).contains(width)) else {
                return Err(crate::error::CompileError::without_span(format!(
                    "parameter '{}' has unsupported entry witness CLI type '{}'",
                    param.name, param.ty
                )));
            };
            decode_hex_arg(&param.name, value, Some(width)).map(EntryWitnessArg::Bytes)
        }
    }
}

fn parse_entry_witness_fixed_arg(param: &ParamMetadata, value: &str, width: usize) -> Result<EntryWitnessArg> {
    match param.ty.as_str() {
        "u128" if width == 16 => parse_integer_arg(&param.name, value, u128::MAX).map(EntryWitnessArg::U128),
        "Address" if width == 32 => {
            let bytes = decode_hex_arg(&param.name, value, Some(32))?;
            let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
                crate::error::CompileError::without_span(format!("parameter '{}' expects exactly 32 hex bytes", param.name))
            })?;
            Ok(EntryWitnessArg::Address(bytes))
        }
        "Hash" if width == 32 => {
            let bytes = decode_hex_arg(&param.name, value, Some(32))?;
            let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
                crate::error::CompileError::without_span(format!("parameter '{}' expects exactly 32 hex bytes", param.name))
            })?;
            Ok(EntryWitnessArg::Hash(bytes))
        }
        _ => decode_hex_arg(&param.name, value, Some(width)).map(EntryWitnessArg::Bytes),
    }
}

fn parse_bool_arg(name: &str, value: &str) -> Result<bool> {
    match value.trim() {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        other => Err(crate::error::CompileError::without_span(format!(
            "parameter '{}' expects bool value true/false/1/0, got '{}'",
            name, other
        ))),
    }
}

fn parse_integer_arg(name: &str, value: &str, max: u128) -> Result<u128> {
    let trimmed = value.trim();
    let parsed = if let Some(hex) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
        u128::from_str_radix(hex, 16)
    } else {
        trimmed.parse::<u128>()
    }
    .map_err(|error| crate::error::CompileError::without_span(format!("parameter '{}' expects integer: {}", name, error)))?;
    if parsed > max {
        return Err(crate::error::CompileError::without_span(format!(
            "parameter '{}' integer value {} is out of range",
            name, parsed
        )));
    }
    Ok(parsed)
}

fn decode_hex_arg(name: &str, value: &str, expected_len: Option<usize>) -> Result<Vec<u8>> {
    let trimmed = value.trim();
    let hex = trimmed
        .strip_prefix("hex:")
        .or_else(|| trimmed.strip_prefix("HEX:"))
        .or_else(|| trimmed.strip_prefix("0x"))
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if !hex.len().is_multiple_of(2) {
        return Err(crate::error::CompileError::without_span(format!("parameter '{}' hex value must contain full bytes", name)));
    }
    let bytes = hex
        .as_bytes()
        .chunks_exact(2)
        .enumerate()
        .map(|(pair_index, pair)| {
            let offset = pair_index * 2;
            let high = hex_nibble(pair[0]).ok_or_else(|| invalid_hex_arg_error(name, offset))?;
            let low = hex_nibble(pair[1]).ok_or_else(|| invalid_hex_arg_error(name, offset))?;
            Ok((high << 4) | low)
        })
        .collect::<Result<Vec<_>>>()?;
    if let Some(expected_len) = expected_len
        && bytes.len() != expected_len
    {
        return Err(crate::error::CompileError::without_span(format!(
            "parameter '{}' expects {} byte(s), got {}",
            name,
            expected_len,
            bytes.len()
        )));
    }
    Ok(bytes)
}

fn invalid_hex_arg_error(name: &str, offset: usize) -> crate::error::CompileError {
    crate::error::CompileError::without_span(format!(
        "parameter '{}' has invalid hex byte at offset {}: invalid digit found in string",
        name, offset
    ))
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn warn_legacy_alias(legacy: &str, canonical: &str, json: bool) {
    if !json && std::io::stderr().is_terminal() {
        eprintln!("warning: `cellc {legacy}` is a compatibility alias; use `cellc {canonical}`");
    }
}

fn json_output(matches: &clap::ArgMatches) -> bool {
    matches.get_flag("json") || matches.get_one::<String>("message-format").is_some_and(|format| format == "json")
}

pub struct CliParser;

impl CliParser {
    pub fn parse() -> Result<Command> {
        let matches = match Self::command().try_get_matches() {
            Ok(matches) => matches,
            Err(error) if matches!(error.kind(), clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion) => {
                error.print().map_err(crate::error::CompileError::from)?;
                std::process::exit(0);
            }
            Err(error) => {
                return Err(crate::error::CompileError::without_span(error.to_string())
                    .with_code("CLI0001")
                    .with_category(crate::error::CompileErrorCategory::Usage));
            }
        };
        let color = matches
            .get_one::<String>("color")
            .map(String::as_str)
            .or_else(|| matches.subcommand().and_then(|(_, subcommand)| subcommand.get_one::<String>("color").map(String::as_str)));
        crate::cli::apply_color_policy(color);
        Ok(Self::parse_matches(matches))
    }

    pub fn command() -> clap::Command {
        use clap::{Arg, ArgAction, Command as ClapCommand};

        ClapCommand::new("cellc")
            .version(crate::VERSION)
            .about("CellScript compiler for CKB blockchain")
            .subcommand_required(true)
            .arg_required_else_help(true)
            .arg(
                Arg::new("color")
                    .long("color")
                    .value_name("WHEN")
                    .value_parser(["auto", "always", "never"])
                    .global(true)
                    .help("Control ANSI colour output: auto, always, or never"),
            )
            .arg(
                Arg::new("json")
                    .long("json")
                    .global(true)
                    .action(ArgAction::SetTrue)
                    .help("Emit one machine-readable JSON result on stdout for success or failure"),
            )
            .arg(
                Arg::new("message-format")
                    .long("message-format")
                    .value_name("FORMAT")
                    .value_parser(["human", "json"])
                    .global(true)
                    .hide(true)
                    .help("Deprecated compatibility alias for --json"),
            )
            .subcommand(
                ClapCommand::new("build")
                    .display_order(10)
                    .about("Compile the current package")
                    .arg(Arg::new("release").long("release").short('r').action(ArgAction::SetTrue).help("Build in release mode"))
                    .arg(Arg::new("target").long("target").short('t').value_name("TARGET").help("Target architecture"))
                    .arg(Arg::new("target-profile").long("target-profile").value_name("PROFILE").help("Target profile: ckb"))
                    .arg(
                        Arg::new("entry-action")
                            .long("entry-action")
                            .value_name("ACTION")
                            .help("Compile only this action as the artifact entrypoint"),
                    )
                    .arg(
                        Arg::new("entry-lock")
                            .long("entry-lock")
                            .value_name("LOCK")
                            .conflicts_with("entry-action")
                            .help("Compile only this lock as the artifact entrypoint"),
                    )
                    .arg(
                        Arg::new("artifact")
                            .long("artifact")
                            .value_name("NAME")
                            .conflicts_with_all(["entry-action", "entry-lock"])
                            .help("Compile the explicitly tagged policy artifact declared in Cell.toml"),
                    )
                    .arg(Arg::new("jobs").long("jobs").short('j').value_name("N").help("Number of parallel jobs"))
                    .arg(Arg::new("features").long("features").value_delimiter(',').num_args(1..).value_name("FEATURES").help("Activate package features"))
                    .arg(Arg::new("all-features").long("all-features").action(ArgAction::SetTrue).help("Activate all package features"))
                    .arg(Arg::new("no-default-features").long("no-default-features").action(ArgAction::SetTrue).help("Do not activate the default feature"))
                    .arg(Arg::new("locked").long("locked").action(ArgAction::SetTrue).help("Require the existing Cell.lock dependency graph"))
                    .arg(Arg::new("frozen").long("frozen").action(ArgAction::SetTrue).help("Require Cell.lock and cached sources without network or lockfile writes"))
                    .arg(Arg::new("offline").long("offline").action(ArgAction::SetTrue).help("Do not access the network while materializing locked sources"))
                    .arg(Arg::new("environment").long("environment").value_name("NAME").help("Select an explicitly declared CKB dependency environment"))

                    .arg(
                        Arg::new("production")
                            .long("production")
                            .action(ArgAction::SetTrue)
                            .help("Reject generated fail-closed runtime paths before writing artifacts"),
                    )
                    .arg(
                        Arg::new("deny-fail-closed").long("deny-fail-closed").action(ArgAction::SetTrue).help(
                            "Reject metadata that contains fail-closed runtime features or obligations before writing artifacts",
                        ),
                    )
                    .arg(
                        Arg::new("deny-ckb-runtime")
                            .long("deny-ckb-runtime")
                            .action(ArgAction::SetTrue)
                            .help("Reject CKB transaction/syscall runtime requirements before writing artifacts"),
                    )
                    .arg(
                        Arg::new("deny-runtime-obligations")
                            .long("deny-runtime-obligations")
                            .action(ArgAction::SetTrue)
                            .help("Reject runtime-required verifier obligations before writing artifacts"),
                    )
                    .arg(
                        Arg::new("primitive-compat")
                            .long("primitive-compat")
                            .value_name("VERSION")
                            .conflicts_with("primitive-strict")
                            .help("Accept primitive syntax from a previous version (e.g. 0.14) with migration hints"),
                    )
                    .arg(
                        Arg::new("primitive-strict")
                            .long("primitive-strict")
                            .value_name("VERSION")
                            .conflicts_with("primitive-compat")
                            .help("Require primitive syntax from a specific version (e.g. 0.15, 0.16, 0.17, or 0.18), reject legacy forms"),
                    )
                    .arg(
                        Arg::new("package")
                            .long("package")
                            .short('p')
                            .value_name("NAME")
                            .help("Build a specific workspace member"),
                    )
                    .arg(
                        Arg::new("workspace")
                            .long("workspace")
                            .action(ArgAction::SetTrue)
                            .help("Build all workspace members"),
                    ),
            )
            .subcommand(
                ClapCommand::new("test")
                    .about("Run the tests")
                    .arg(Arg::new("filter").value_name("FILTER").help("Filter tests by name"))
                    .arg(
                        Arg::new("backend")
                            .long("backend")
                            .value_name("BACKEND")
                            .value_parser(["simulator", "ckb-vm", "all"])
                            .help("Execution backend; required unless --no-run: simulator, ckb-vm, or all"),
                    )
                    .arg(
                        Arg::new("no-run")
                            .long("no-run")
                            .action(ArgAction::SetTrue)
                            .help("Compile tests without attempting execution"),
                    )
                    .arg(Arg::new("nocapture").long("nocapture").action(ArgAction::SetTrue).help("Don't capture stdout"))
                    .arg(Arg::new("fail-fast").long("fail-fast").action(ArgAction::SetTrue).help("Stop on first failure"))
                    .arg(Arg::new("doc").long("doc").action(ArgAction::SetTrue).help("Generate docs before compiling tests"))
                    .arg(Arg::new("features").long("features").value_delimiter(',').num_args(1..).value_name("FEATURES").help("Activate package features"))
                    .arg(Arg::new("all-features").long("all-features").action(ArgAction::SetTrue).help("Activate all package features"))
                    .arg(Arg::new("no-default-features").long("no-default-features").action(ArgAction::SetTrue).help("Do not activate the default feature"))
                    .arg(Arg::new("locked").long("locked").action(ArgAction::SetTrue).help("Require the existing Cell.lock dependency graph"))
                    .arg(Arg::new("frozen").long("frozen").action(ArgAction::SetTrue).help("Require cached locked sources without network or lockfile writes"))
                    .arg(Arg::new("offline").long("offline").action(ArgAction::SetTrue).help("Do not access the network while materializing locked sources"))
                    .arg(Arg::new("environment").long("environment").value_name("NAME").help("Select an explicitly declared CKB dependency environment"))
                    ,
            )
            .subcommand(
                ClapCommand::new("doc")
                    .about("Generate documentation")
                    .arg(Arg::new("open").long("open").short('o').action(ArgAction::SetTrue).help("Open docs in browser"))

                    .arg(
                        Arg::new("format")
                            .long("format")
                            .value_name("FORMAT")
                            .default_value("html")
                            .help("Output format: html, markdown, json"),
                    ),
            )
            .subcommand(
                ClapCommand::new("fmt")
                    .display_order(130)
                    .about("Format source code")
                    .arg(Arg::new("check").long("check").action(ArgAction::SetTrue).help("Check formatting without modifying files"))

                    .arg(Arg::new("files").value_name("FILES").num_args(1..).help("Files to format")),
            )
            .subcommand(
                ClapCommand::new("init")
                    .display_order(140)
                    .about("Create a new package")
                    .arg(Arg::new("name").value_name("NAME").help("Package name"))
                    .arg(Arg::new("path").value_name("PATH").help("Path to create package"))
                    .arg(Arg::new("lib").long("lib").action(ArgAction::SetTrue).help("Create a library package"))
                    .arg(Arg::new("namespace").long("namespace").value_name("NAMESPACE").help("Package namespace for registry publishing"))
                    ,
            )
            .subcommand(
                ClapCommand::new("new")
                    .about("Create a new package directory")
                    .arg(Arg::new("name").value_name("NAME").required(true).help("Package name"))
                    .arg(Arg::new("path").long("path").value_name("PATH").help("Path to create package"))
                    .arg(Arg::new("lib").long("lib").action(ArgAction::SetTrue).help("Create a library package"))
                    .arg(
                        Arg::new("vcs")
                            .long("vcs")
                            .value_name("VCS")
                            .default_value("git")
                            .value_parser(["git", "none"])
                            .help("Initialize version control: git or none"),
                    )
                    ,
            )
            .subcommand(
                ClapCommand::new("add")
                    .about("Add dependencies")
                    .arg(Arg::new("crates").value_name("CRATES").required(true).num_args(1..).help("Crates to add"))
                    .arg(Arg::new("package-name").long("package").value_name("NAME").help("Declared package name when it differs from the local alias"))
                    .arg(Arg::new("dev").long("dev").action(ArgAction::SetTrue).help("Add as dev dependency"))
                    .arg(Arg::new("build").long("build").action(ArgAction::SetTrue).help("Add as build dependency"))
                    .arg(Arg::new("git").long("git").value_name("URL").help("Add a git dependency source"))
                    .arg(Arg::new("path").long("path").value_name("PATH").help("Add a local path dependency source"))
                    .arg(
                        Arg::new("use-environment")
                            .long("use-environment")
                            .value_name("NAME")
                            .conflicts_with("environment-independent")
                            .help("Map this edge to an exact dependency-local environment with the root chain identity"),
                    )
                    .arg(
                        Arg::new("environment-independent")
                            .long("environment-independent")
                            .action(ArgAction::SetTrue)
                            .conflicts_with("use-environment")
                            .help("Do not apply dependency-local environment overrides on this edge"),
                    )
                    ,
            )
            .subcommand(
                ClapCommand::new("clean")
                    .about("Remove build artifacts")

                    .arg(
                        Arg::new("cache")
                            .long("cache")
                            .action(ArgAction::SetTrue)
                            .help("Also remove incremental compilation caches below the current workspace"),
                    ),
            )
            .subcommand(
                ClapCommand::new("remove")
                    .about("Remove dependencies")
                    .arg(Arg::new("crates").value_name("CRATES").required(true).num_args(1..).help("Crates to remove"))
                    .arg(Arg::new("dev").long("dev").action(ArgAction::SetTrue).help("Remove from dev dependency section"))
                    .arg(Arg::new("build").long("build").action(ArgAction::SetTrue).help("Remove from build dependency section"))
                    ,
            )
            .subcommand(ClapCommand::new("repl").about("Start interactive REPL"))
            .subcommand(
                ClapCommand::new("check")
                    .display_order(20)
                    .about("Type-check and lower the current package without writing artifacts")
                    .arg(
                        Arg::new("artifact")
                            .long("artifact")
                            .value_name("NAME")
                            .help("Check the explicitly tagged policy artifact declared in Cell.toml"),
                    )
                    .arg(
                        Arg::new("all-targets")
                            .long("all-targets")
                            .action(ArgAction::SetTrue)
                            .help("Also check the current ELF-compatible target path"),
                    )
                    .arg(Arg::new("target-profile").long("target-profile").value_name("PROFILE").help("Target profile: ckb"))
                    .arg(Arg::new("features").long("features").value_delimiter(',').num_args(1..).value_name("FEATURES").help("Activate package features"))
                    .arg(Arg::new("all-features").long("all-features").action(ArgAction::SetTrue).help("Activate all package features"))
                    .arg(Arg::new("no-default-features").long("no-default-features").action(ArgAction::SetTrue).help("Do not activate the default feature"))
                    .arg(Arg::new("locked").long("locked").action(ArgAction::SetTrue).help("Require the existing Cell.lock dependency graph"))
                    .arg(Arg::new("frozen").long("frozen").action(ArgAction::SetTrue).help("Require cached locked sources without network or lockfile writes"))
                    .arg(Arg::new("offline").long("offline").action(ArgAction::SetTrue).help("Do not access the network while materializing locked sources"))
                    .arg(Arg::new("environment").long("environment").value_name("NAME").help("Select an explicitly declared CKB dependency environment"))

                    .arg(
                        Arg::new("production")
                            .long("production")
                            .action(ArgAction::SetTrue)
                            .help("Reject generated fail-closed runtime paths"),
                    )
                    .arg(
                        Arg::new("deny-fail-closed")
                            .long("deny-fail-closed")
                            .action(ArgAction::SetTrue)
                            .help("Reject metadata that contains fail-closed runtime features or obligations"),
                    )
                    .arg(
                        Arg::new("deny-ckb-runtime")
                            .long("deny-ckb-runtime")
                            .action(ArgAction::SetTrue)
                            .help("Reject CKB transaction/syscall runtime requirements"),
                    )
                    .arg(
                        Arg::new("deny-runtime-obligations")
                            .long("deny-runtime-obligations")
                            .action(ArgAction::SetTrue)
                            .help("Reject runtime-required verifier obligations"),
                    )
                    .arg(
                        Arg::new("primitive-compat")
                            .long("primitive-compat")
                            .value_name("VERSION")
                            .conflicts_with("primitive-strict")
                            .help("Accept primitive syntax from a previous version (e.g. 0.14) with migration hints"),
                    )
                    .arg(
                        Arg::new("primitive-strict")
                            .long("primitive-strict")
                            .value_name("VERSION")
                            .conflicts_with("primitive-compat")
                            .help("Require primitive syntax from a specific version (e.g. 0.15, 0.16, 0.17, or 0.18), reject legacy forms"),
                    )
                    .arg(
                        Arg::new("package")
                            .long("package")
                            .short('p')
                            .value_name("NAME")
                            .help("Check a specific workspace member"),
                    )
                    .arg(
                        Arg::new("workspace")
                            .long("workspace")
                            .action(ArgAction::SetTrue)
                            .help("Check all workspace members"),
                    ),
            )
            .subcommand(
                ClapCommand::new("metadata")
                    .display_order(30)
                    .about("Emit compile metadata for lowering, scheduler, and CKB runtime auditing")
                    .arg(Arg::new("input").value_name("INPUT").help("Input .cell file, package directory, or Cell.toml"))
                    .arg(Arg::new("artifact").long("artifact").value_name("NAME").help("Inspect the declared policy artifact without generating machine code"))
                    .arg(Arg::new("output").long("output").short('o').value_name("FILE").help("Write JSON metadata to a file"))
                    .arg(Arg::new("target").long("target").short('t').value_name("TARGET").help("Target architecture"))
                    .arg(Arg::new("target-profile").long("target-profile").value_name("PROFILE").help("Target profile: ckb")),
            )
            .subcommand(
                ClapCommand::new("expand")
                    .display_order(31)
                    .about("Render the canonical typed semantic foundation; the rendering is not a hash boundary")
                    .arg(Arg::new("input").value_name("INPUT").help("Input .cell file, package directory, or Cell.toml"))
                    .arg(Arg::new("artifact").long("artifact").value_name("NAME").help("Expand the declared policy artifact without generating machine code"))
                    .arg(Arg::new("output").long("output").short('o').value_name("FILE").help("Write the expansion to a file"))
                    .arg(Arg::new("target").long("target").short('t').value_name("TARGET").help("Target architecture"))
                    .arg(Arg::new("target-profile").long("target-profile").value_name("PROFILE").help("Target profile: ckb")),
            )
            .subcommand(
                ClapCommand::new("migrate")
                    .display_order(31)
                    .about("Generate a review-only, differentially verified Edition 2027 source candidate")
                    .arg(Arg::new("input").value_name("INPUT").help("Edition 2026 .cell file, package directory, or Cell.toml"))
                    .arg(
                        Arg::new("to")
                            .long("to")
                            .value_name("EDITION")
                            .default_value("2027")
                            .value_parser(["2027"])
                            .help("Target source edition"),
                    )
                    .arg(
                        Arg::new("output")
                            .long("output")
                            .short('o')
                            .value_name("FILE")
                            .help("Write the candidate source, or the report with --json, to a file"),
                    ),
            )
            .subcommand(
                ClapCommand::new("interface")
                    .display_order(32)
                    .about("Emit the canonical public package interface and its CKB hash")
                    .arg(Arg::new("input").value_name("INPUT").help("Input .cell file, package directory, or Cell.toml"))
                    .arg(Arg::new("output").long("output").short('o').value_name("FILE").help("Write the interface JSON to a file"))
                    .arg(Arg::new("target").long("target").short('t').value_name("TARGET").help("Target architecture"))
                    .arg(Arg::new("target-profile").long("target-profile").value_name("PROFILE").help("Target profile: ckb")),
            )
            .subcommand(
                ClapCommand::new("interface-diff")
                    .display_order(32)
                    .about("Compare source API, layout, ABI, effects, builders, and deployment contracts")
                    .arg(Arg::new("old").long("old").value_name("INPUT_OR_JSON").required(true).help("Previous source/package or interface JSON"))
                    .arg(Arg::new("new").long("new").value_name("INPUT_OR_JSON").required(true).help("Candidate source/package or interface JSON"))
                    .arg(Arg::new("output").long("output").short('o').value_name("FILE").help("Write the compatibility report to a file")),
            )
            .subcommand(
                ClapCommand::new("constraints")
                    .about("Emit profile-aware production constraints for compiler, builder, CI, and acceptance gates")
                    .arg(Arg::new("input").value_name("INPUT").help("Input .cell file, package directory, or Cell.toml"))
                    .arg(Arg::new("output").long("output").short('o').value_name("FILE").help("Write JSON constraints to a file"))
                    .arg(Arg::new("target").long("target").short('t').value_name("TARGET").help("Target architecture"))
                    .arg(Arg::new("target-profile").long("target-profile").value_name("PROFILE").help("Target profile: ckb"))
                    .arg(
                        Arg::new("entry-action")
                            .long("entry-action")
                            .value_name("ACTION")
                            .help("Report constraints for this action entry"),
                    )
                    .arg(Arg::new("entry-lock").long("entry-lock").value_name("LOCK").help("Report constraints for this lock entry")),
            )
            .subcommand(
                ClapCommand::new("abi")
                    .about("Explain the generated _cellscript_entry witness ABI for an action or lock")
                    .arg(Arg::new("input").value_name("INPUT").help("Input .cell file, package directory, or Cell.toml"))
                    .arg(Arg::new("output").long("output").short('o').value_name("FILE").help("Write JSON ABI report to a file"))
                    .arg(Arg::new("target").long("target").short('t').value_name("TARGET").help("Target architecture"))
                    .arg(Arg::new("target-profile").long("target-profile").value_name("PROFILE").help("Target profile: ckb"))
                    .arg(Arg::new("action").long("action").value_name("NAME").help("Explain ABI for this action"))
                    .arg(Arg::new("lock").long("lock").value_name("NAME").help("Explain ABI for this lock")),
            )
            .subcommand(
                ClapCommand::new("scheduler-plan")
                    .about("Consume scheduler hints and emit a CKB admission/conflict policy report")
                    .arg(Arg::new("input").value_name("INPUT").help("Input .cell file, package directory, or Cell.toml"))
                    .arg(Arg::new("output").long("output").short('o').value_name("FILE").help("Write JSON scheduler plan to a file"))
                    .arg(Arg::new("target").long("target").short('t').value_name("TARGET").help("Target architecture"))
                    .arg(Arg::new("target-profile").long("target-profile").value_name("PROFILE").help("Target profile: ckb")),
            )
            .subcommand(
                ClapCommand::new("ckb-hash")
                    .about("Compute CKB default Blake2b-256 hashes for builders, manifests, and release evidence")
                    .arg(Arg::new("input").value_name("TEXT").help("UTF-8 text to hash; omitted input hashes empty bytes"))
                    .arg(Arg::new("hex").long("hex").value_name("HEX").help("Hex bytes to hash"))
                    .arg(Arg::new("file").long("file").value_name("FILE").help("File bytes to hash"))
                    ,
            )
            .subcommand(
                ClapCommand::new("ckb-std-compat")
                    .about("Report the ckb-std ABI compatibility boundary for CellScript's inline CKB backend")
                    ,
            )
            .subcommand(
                ClapCommand::new("explain")
                    .about("Explain runtime errors, target profiles, ProofPlan records, assumptions, generics, and graph views")
                    .arg_required_else_help(true)
                    .arg(Arg::new("code").value_name("CODE").help("Runtime error code, E-code, or error name"))

                    .subcommand(
                        ClapCommand::new("profile")
                            .about("Explain a CellScript target profile semantic contract")
                            .arg(Arg::new("profile").value_name("PROFILE").required(true).help("Target profile name, e.g. ckb"))
                            ,
                    )
                    .subcommand(
                        ClapCommand::new("proof")
                            .about("Explain Covenant ProofPlan trigger, scope, reads, coverage, and on-chain status")
                            .arg(Arg::new("input").value_name("INPUT").help("Input .cell file, package directory, or Cell.toml"))
                            .arg(Arg::new("target").long("target").short('t').value_name("TARGET").help("Target architecture"))
                            .arg(Arg::new("target-profile").long("target-profile").value_name("PROFILE").help("Target profile: ckb"))
                            ,
                    )
                    .subcommand(
                        ClapCommand::new("assumptions")
                            .about("Explain v0.16 builder assumptions derived from ProofPlan metadata")
                            .arg(Arg::new("input").value_name("INPUT").help("Input .cell file, package directory, or Cell.toml"))
                            .arg(Arg::new("target").long("target").short('t').value_name("TARGET").help("Target architecture"))
                            .arg(Arg::new("target-profile").long("target-profile").value_name("PROFILE").help("Target profile: ckb"))
                            ,
                    )
                    .subcommand(
                        ClapCommand::new("generics")
                            .about("Explain value-generic monomorphizations and bounded collection instantiations")
                            .arg(Arg::new("input").value_name("INPUT").help("Input .cell file, package directory, or Cell.toml"))
                            .arg(Arg::new("target").long("target").short('t').value_name("TARGET").help("Target architecture"))
                            .arg(Arg::new("target-profile").long("target-profile").value_name("PROFILE").help("Target profile: ckb"))
                            ,
                    )
                    .subcommand(
                        ClapCommand::new("graph")
                            .about("Derive a cyclic ProtocolGraph audit view from compile metadata")
                            .arg(Arg::new("input").value_name("INPUT").help("Input .cell file, package directory, or Cell.toml"))
                            .arg(Arg::new("target").long("target").short('t').value_name("TARGET").help("Target architecture"))
                            .arg(Arg::new("target-profile").long("target-profile").value_name("PROFILE").help("Target profile: ckb"))
                            .arg(
                                Arg::new("format")
                                    .long("format")
                                    .value_name("FORMAT")
                                    .value_parser(["json", "mermaid"])
                                    .help("ProtocolGraph output format"),
                            )
                            ,
                    ),
            )
            .subcommand(
                ClapCommand::new("explain-profile")
                    .hide(true)
                    .about("Explain a CellScript target profile semantic contract")
                    .arg(Arg::new("profile").value_name("PROFILE").required(true).help("Target profile name, e.g. ckb"))
                    ,
            )
            .subcommand(
                ClapCommand::new("explain-proof")
                    .hide(true)
                    .about("Explain Covenant ProofPlan trigger, scope, reads, coverage, and on-chain status")
                    .arg(Arg::new("input").value_name("INPUT").help("Input .cell file, package directory, or Cell.toml"))
                    .arg(Arg::new("target").long("target").short('t').value_name("TARGET").help("Target architecture"))
                    .arg(Arg::new("target-profile").long("target-profile").value_name("PROFILE").help("Target profile: ckb"))
                    ,
            )
            .subcommand(
                ClapCommand::new("explain-assumptions")
                    .hide(true)
                    .about("Explain v0.16 builder assumptions derived from ProofPlan metadata")
                    .arg(Arg::new("input").value_name("INPUT").help("Input .cell file, package directory, or Cell.toml"))
                    .arg(Arg::new("target").long("target").short('t').value_name("TARGET").help("Target architecture"))
                    .arg(Arg::new("target-profile").long("target-profile").value_name("PROFILE").help("Target profile: ckb"))
                    ,
            )
            .subcommand(
                ClapCommand::new("explain-generics")
                    .hide(true)
                    .about("Explain value-generic monomorphizations and bounded collection instantiations")
                    .arg(Arg::new("input").value_name("INPUT").help("Input .cell file, package directory, or Cell.toml"))
                    .arg(Arg::new("target").long("target").short('t').value_name("TARGET").help("Target architecture"))
                    .arg(Arg::new("target-profile").long("target-profile").value_name("PROFILE").help("Target profile: ckb"))
                    ,
            )
            .subcommand(
                ClapCommand::new("explain-graph")
                    .hide(true)
                    .about("Derive a cyclic ProtocolGraph audit view from compile metadata")
                    .arg(Arg::new("input").value_name("INPUT").help("Input .cell file, package directory, or Cell.toml"))
                    .arg(Arg::new("target").long("target").short('t').value_name("TARGET").help("Target architecture"))
                    .arg(Arg::new("target-profile").long("target-profile").value_name("PROFILE").help("Target profile: ckb"))
                    .arg(
                        Arg::new("format")
                            .long("format")
                            .value_name("FORMAT")
                            .value_parser(["json", "mermaid"])
                            .help("ProtocolGraph output format"),
                    )
                    ,
            )
            .subcommand(
                ClapCommand::new("opt-report")
                    .about("Compile O0..O3 and emit artifact-size/constraints comparison evidence")
                    .arg(Arg::new("input").value_name("INPUT").help("Input .cell file, package directory, or Cell.toml"))
                    .arg(
                        Arg::new("output")
                            .long("output")
                            .short('o')
                            .value_name("FILE")
                            .help("Write JSON optimization report to a file"),
                    )
                    .arg(Arg::new("target").long("target").short('t').value_name("TARGET").help("Target architecture"))
                    .arg(Arg::new("target-profile").long("target-profile").value_name("PROFILE").help("Target profile: ckb")),
            )
            .subcommand(
                ClapCommand::new("proof-diff")
                    .about("Diff ProofPlan semantics between two metadata files")
                    .arg(Arg::new("old").value_name("OLD_METADATA").required(true))
                    .arg(Arg::new("new").value_name("NEW_METADATA").required(true))
                    ,
            )
            .subcommand(
                ClapCommand::new("profile")
                    .about("Emit v0.16 cycle/profile summary per action, lock, and ProofPlan record")
                    .arg(Arg::new("input").value_name("INPUT").help("Input .cell file, package directory, or Cell.toml"))
                    .arg(Arg::new("entry").long("entry").value_name("NAME").help("Limit profile to one action or lock"))
                    .arg(Arg::new("target").long("target").short('t').value_name("TARGET").help("Target architecture"))
                    .arg(Arg::new("target-profile").long("target-profile").value_name("PROFILE").help("Target profile: ckb"))
                    ,
            )
            .subcommand(
                ClapCommand::new("tx")
                    .display_order(70)
                    .about("Validate, solve, and trace transaction evidence")
                    .subcommand_required(true)
                    .arg_required_else_help(true)
                    .subcommand(
                        ClapCommand::new("validate")
                            .about("Validate a transaction JSON against v0.16 builder assumptions before signing")
                            .arg(Arg::new("against").long("against").value_name("METADATA").required(true).help("Metadata JSON"))
                            .arg(Arg::new("tx").long("tx").value_name("TX_JSON").required(true).help("Transaction JSON"))
                            ,
                    )
                    .subcommand(
                        ClapCommand::new("solve")
                            .about("Emit a deterministic v0.16 transaction template from metadata and builder assumptions")
                            .arg(Arg::new("input").value_name("INPUT").help("Input .cell file, package directory, or Cell.toml"))
                            .arg(Arg::new("output").long("output").short('o').value_name("FILE").help("Write JSON solver template"))
                            .arg(Arg::new("target").long("target").short('t').value_name("TARGET").help("Target architecture"))
                            .arg(Arg::new("target-profile").long("target-profile").value_name("PROFILE").help("Target profile: ckb"))
                            ,
                    )
                    .subcommand(
                        ClapCommand::new("trace")
                            .about("Trace a transaction JSON against v0.16 builder assumptions")
                            .arg(Arg::new("against").long("against").value_name("METADATA").required(true).help("Metadata JSON"))
                            .arg(Arg::new("tx").long("tx").value_name("TX_JSON").required(true).help("Transaction JSON"))
                            ,
                    ),
            )
            .subcommand(
                ClapCommand::new("trace-tx")
                    .hide(true)
                    .about("Trace a transaction JSON against v0.16 builder assumptions")
                    .arg(Arg::new("against").long("against").value_name("METADATA").required(true).help("Metadata JSON"))
                    .arg(Arg::new("tx").value_name("TX_JSON").required(true).help("Transaction JSON"))
                    ,
            )
            .subcommand(
                ClapCommand::new("audit-bundle")
                    .about("Generate a v0.16 audit bundle linking metadata, ProofPlan, assumptions, and profile data")
                    .arg(Arg::new("input").value_name("INPUT").help("Input .cell file, package directory, or Cell.toml"))
                    .arg(Arg::new("output").long("output").short('o').value_name("DIR").help("Output directory"))
                    .arg(Arg::new("target").long("target").short('t').value_name("TARGET").help("Target architecture"))
                    .arg(Arg::new("target-profile").long("target-profile").value_name("PROFILE").help("Target profile: ckb"))
                    ,
            )
            .subcommand(
                ClapCommand::new("validate-tx")
                    .hide(true)
                    .about("Validate a transaction JSON against v0.16 builder assumptions before signing")
                    .arg(Arg::new("against").long("against").value_name("METADATA").required(true).help("Metadata JSON"))
                    .arg(Arg::new("tx").value_name("TX_JSON").required(true).help("Transaction JSON"))
                    ,
            )
            .subcommand(
                ClapCommand::new("solve-tx")
                    .hide(true)
                    .about("Emit a deterministic v0.16 transaction template from metadata and builder assumptions")
                    .arg(Arg::new("input").value_name("INPUT").help("Input .cell file, package directory, or Cell.toml"))
                    .arg(Arg::new("output").long("output").short('o').value_name("FILE").help("Write JSON solver template"))
                    .arg(Arg::new("target").long("target").short('t').value_name("TARGET").help("Target architecture"))
                    .arg(Arg::new("target-profile").long("target-profile").value_name("PROFILE").help("Target profile: ckb"))
                    ,
            )
            .subcommand(
                ClapCommand::new("verify-ckb-fixtures")
                    .about("Verify standard CKB compatibility fixtures with the deterministic model runner")
                    .arg(Arg::new("manifest").value_name("MANIFEST_JSON").required(true).help("CKB fixture manifest JSON"))
                    ,
            )
            .subcommand(
                ClapCommand::new("deploy")
                    .display_order(80)
                    .about("Plan, verify, diff, and lock deployment evidence")
                    .subcommand_required(true)
                    .arg_required_else_help(true)
                    .subcommand(
                        ClapCommand::new("plan")
                            .about("Emit a reproducible v0.16 deployment plan")
                            .arg(Arg::new("input").value_name("INPUT").help("Input .cell file, package directory, or Cell.toml"))
                            .arg(Arg::new("output").long("output").short('o').value_name("FILE").help("Write JSON deploy plan"))
                            .arg(Arg::new("target").long("target").short('t').value_name("TARGET").help("Target architecture"))
                            .arg(Arg::new("target-profile").long("target-profile").value_name("PROFILE").help("Target profile: ckb"))
                            ,
                    )
                    .subcommand(
                        ClapCommand::new("verify")
                            .about("Verify a v0.16 deployment plan schema and local integrity fields")
                            .arg(Arg::new("plan").long("plan").value_name("DEPLOY_PLAN").required(true).help("Deployment plan JSON"))
                            ,
                    )
                    .subcommand(
                        ClapCommand::new("diff")
                            .about("Diff two v0.16 deployment plans")
                            .arg(Arg::new("old").long("old").value_name("OLD_DEPLOY_PLAN").required(true).help("Previous deployment plan JSON"))
                            .arg(Arg::new("new").long("new").value_name("NEW_DEPLOY_PLAN").required(true).help("New deployment plan JSON"))
                            ,
                    )
                    .subcommand(
                        ClapCommand::new("lock-deps")
                            .about("Emit a v0.16 dependency lock from deployment metadata")
                            .arg(Arg::new("input").value_name("INPUT").help("Input .cell file, package directory, or Cell.toml"))
                            .arg(Arg::new("output").long("output").short('o').value_name("FILE").help("Write dependency lock JSON"))
                            .arg(Arg::new("target").long("target").short('t').value_name("TARGET").help("Target architecture"))
                            .arg(Arg::new("target-profile").long("target-profile").value_name("PROFILE").help("Target profile: ckb"))
                            ,
                    ),
            )
            .subcommand(
                ClapCommand::new("deploy-plan")
                    .hide(true)
                    .about("Emit a reproducible v0.16 deployment plan")
                    .arg(Arg::new("input").value_name("INPUT").help("Input .cell file, package directory, or Cell.toml"))
                    .arg(Arg::new("output").long("output").short('o').value_name("FILE").help("Write JSON deploy plan"))
                    .arg(Arg::new("target").long("target").short('t').value_name("TARGET").help("Target architecture"))
                    .arg(Arg::new("target-profile").long("target-profile").value_name("PROFILE").help("Target profile: ckb"))
                    ,
            )
            .subcommand(
                ClapCommand::new("verify-deploy")
                    .hide(true)
                    .about("Verify a v0.16 deployment plan schema and local integrity fields")
                    .arg(Arg::new("plan").value_name("DEPLOY_PLAN").required(true))
                    ,
            )
            .subcommand(
                ClapCommand::new("diff-deploy")
                    .hide(true)
                    .about("Diff two v0.16 deployment plans")
                    .arg(Arg::new("old").value_name("OLD_DEPLOY_PLAN").required(true))
                    .arg(Arg::new("new").value_name("NEW_DEPLOY_PLAN").required(true))
                    ,
            )
            .subcommand(
                ClapCommand::new("lock-deps")
                    .hide(true)
                    .about("Emit a v0.16 dependency lock from deployment metadata")
                    .arg(Arg::new("input").value_name("INPUT").help("Input .cell file, package directory, or Cell.toml"))
                    .arg(Arg::new("output").long("output").short('o').value_name("FILE").help("Write dependency lock JSON"))
                    .arg(Arg::new("target").long("target").short('t').value_name("TARGET").help("Target architecture"))
                    .arg(Arg::new("target-profile").long("target-profile").value_name("PROFILE").help("Target profile: ckb"))
                    ,
            )
            .subcommand(
                ClapCommand::new("action")
                    .display_order(50)
                    .about("Plan and explain action-level transaction builder inputs")
                    .subcommand(
                    ClapCommand::new("build")
                        .about("Emit a builder plan for a CellScript action without signing or submitting a transaction")
                        .arg(Arg::new("input").value_name("INPUT").help("Input .cell file, package directory, or Cell.toml"))
                        .arg(Arg::new("action").long("action").value_name("NAME").help("Action to plan; defaults to the first action"))
                        .arg(Arg::new("output").long("output").short('o').value_name("FILE").help("Write JSON builder plan to a file"))
                        .arg(Arg::new("target").long("target").short('t').value_name("TARGET").help("Target architecture"))
                        .arg(Arg::new("target-profile").long("target-profile").value_name("PROFILE").help("Target profile: ckb"))
                        .arg(
                            Arg::new("fabric-intent")
                                .long("fabric-intent")
                                .action(ArgAction::SetTrue)
                                .help("Emit a CellFabric intent envelope instead of the raw CellScript action plan"),
                        )
                        .arg(
                            Arg::new("json").long("json").action(ArgAction::SetTrue).help("Emit a machine-readable JSON builder plan"),
                        ),
                ),
            )
            .subcommand(
                ClapCommand::new("gen-builder")
                    .display_order(60)
                    .about("Generate a registry-bound action builder package from CellScript metadata")
                    .arg(Arg::new("input").value_name("INPUT").help("Input .cell file, package directory, or Cell.toml"))
                    .arg(Arg::new("artifact").long("artifact").value_name("NAME").help("Select one declared policy artifact; metadata input must match"))
                    .arg(
                        Arg::new("metadata")
                            .long("metadata")
                            .value_name("FILE")
                            .help("Read compile metadata JSON instead of compiling INPUT"),
                    )
                    .arg(
                        Arg::new("lockfile")
                            .long("lockfile")
                            .value_name("FILE")
                            .help("Verify generated builder identity against Cell.lock before writing"),
                    )
                    .arg(
                        Arg::new("deployed")
                            .long("deployed")
                            .value_name("FILE")
                            .help("Verify generated builder deployment identity against Deployed.toml before writing"),
                    )
                    .arg(
                        Arg::new("deployment-network")
                            .long("deployment-network")
                            .value_name("NAME")
                            .help("Verify and embed only this deployment network when using --deployed"),
                    )
                    .arg(
                        Arg::new("target")
                            .long("target")
                            .value_name("TARGET")
                            .required(true)
                            .value_parser(["typescript"])
                            .help("Generated builder target"),
                    )
                    .arg(Arg::new("action").long("action").value_name("NAME").help("Generate only this action; defaults to all actions"))
                    .arg(Arg::new("output").long("output").short('o').value_name("DIR").help("Output package directory"))
                    .arg(Arg::new("target-profile").long("target-profile").value_name("PROFILE").help("Target profile when compiling INPUT: ckb"))
                    .arg(Arg::new("package-name").long("package-name").value_name("NAME").help("Generated package.json name"))
                    ,
            )
            .subcommand(
                ClapCommand::new("entry-witness")
                    .about("Encode witness bytes for the generated _cellscript_entry wrapper")
                    .arg(Arg::new("input").value_name("INPUT").help("Input .cell file, package directory, or Cell.toml"))
                    .arg(Arg::new("artifact").long("artifact").value_name("NAME").requires_all(["action", "script-hash"]).conflicts_with("lock").help("Encode one declared Type-policy request; requires action and full Script hash"))
                    .arg(Arg::new("script-hash").long("script-hash").value_name("HEX").requires("artifact").help("Full deployed 32-byte Script hash; caller-supplied routing identity, not authentication"))
                    .arg(Arg::new("action").long("action").value_name("NAME").help("Encode witness bytes for this action"))
                    .arg(Arg::new("lock").long("lock").value_name("NAME").help("Encode witness bytes for this lock"))
                    .arg(
                        Arg::new("arg")
                            .long("arg")
                            .value_name("VALUE")
                            .num_args(1)
                            .action(ArgAction::Append)
                            .help("Witness payload argument; schema-backed params are omitted, byte params use hex"),
                    )
                    .arg(Arg::new("output").long("output").short('o').value_name("FILE").help("Write raw witness bytes to a file"))
                    .arg(Arg::new("target").long("target").short('t').value_name("TARGET").help("Target architecture"))
                    .arg(Arg::new("target-profile").long("target-profile").value_name("PROFILE").help("Target profile: ckb"))
                    ,
            )
            .subcommand(
                ClapCommand::new("receipt")
                    .display_order(40)
                    .about("Emit an authenticated compile-receipt envelope over metadata and artifact hashes")
                    .arg(Arg::new("input").value_name("INPUT").help("Input .cell file, package directory, or Cell.toml"))
                    .arg(
                        Arg::new("output")
                            .long("output")
                            .short('o')
                            .value_name("FILE")
                            .required(true)
                            .help("Write the compile receipt JSON to this file"),
                    )
                    .arg(Arg::new("target").long("target").short('t').value_name("TARGET").help("Target architecture"))
                    .arg(Arg::new("target-profile").long("target-profile").value_name("PROFILE").help("Target profile: ckb"))
                    ,
            )
            .subcommand(
                ClapCommand::new("sign-receipt")
                    .display_order(41)
                    .about("Append an Ed25519 signature to a compile receipt")
                    .arg(Arg::new("receipt").value_name("RECEIPT").required(true).help("Compile receipt JSON to sign"))
                    .arg(
                        Arg::new("role")
                            .long("role")
                            .value_name("ROLE")
                            .required(true)
                            .help("Signature role to record: compiler or publisher"),
                    )
                    .arg(
                        Arg::new("key")
                            .long("key")
                            .value_name("KEY")
                            .required(true)
                            .help("Ed25519 PKCS#8 key as a file path, @file, or base64 DER"),
                    )
                    .arg(
                        Arg::new("output")
                            .long("output")
                            .short('o')
                            .value_name("FILE")
                            .help("Write the signed receipt here; defaults to updating RECEIPT in place"),
                    )
                    ,
            )
            .subcommand(
                ClapCommand::new("verify-receipt")
                    .display_order(42)
                    .about("Verify a compile receipt against metadata, artifact bytes, and Ed25519 signatures")
                    .arg(Arg::new("receipt").value_name("RECEIPT").required(true).help("Compile receipt JSON to verify"))
                    .arg(
                        Arg::new("metadata")
                            .long("metadata")
                            .short('m')
                            .value_name("FILE")
                            .required(true)
                            .help("Metadata JSON sidecar to bind to the receipt"),
                    )
                    .arg(
                        Arg::new("artifact")
                            .long("artifact")
                            .short('a')
                            .value_name("FILE")
                            .required(true)
                            .help("Artifact bytes to bind to the receipt"),
                    )
                    ,
            )
            .subcommand(
                ClapCommand::new("protocol")
                    .display_order(42)
                    .about("Compose and inspect artifact-only multi-Script protocols")
                    .arg_required_else_help(true)
                    .subcommand(
                        ClapCommand::new("bundle")
                            .about("Compose independently checked artifacts into one transaction skeleton")
                            .arg_required_else_help(true)
                            .subcommand(
                                ClapCommand::new("check")
                                    .about("Verify artifact identities and reject transaction-role conflicts offline")
                                    .arg(
                                        Arg::new("manifest")
                                            .value_name("BUNDLE_JSON")
                                            .required(true)
                                            .help("cellscript-protocol-bundle-input-v1 manifest with relative checked-artifact paths"),
                                    )
                                    .arg(
                                        Arg::new("output")
                                            .long("output")
                                            .short('o')
                                            .value_name("REPORT_JSON")
                                            .help("Write the resolved bundle, conflicts, and evidence template"),
                                    ),
                            ),
                    ),
            )
            .subcommand(
                ClapCommand::new("verify-artifact")
                    .display_order(43)
                    .about("Verify an emitted CellScript artifact against its metadata sidecar")
                    .arg(Arg::new("artifact").value_name("ARTIFACT").required(true).help("Artifact file to verify"))
                    .arg(
                        Arg::new("metadata")
                            .long("metadata")
                            .short('m')
                            .value_name("FILE")
                            .help("Metadata JSON file; defaults to ARTIFACT.meta.json"),
                    )
                    .arg(
                        Arg::new("receipt")
                            .long("receipt")
                            .value_name("FILE")
                            .help("Also verify a compile receipt against the artifact and metadata"),
                    )
                    .arg(
                        Arg::new("lowering-record")
                            .long("lowering-record")
                            .value_name("FILE")
                            .help("Canonical lowering record; defaults to ARTIFACT.lowering.json for ELF"),
                    )
                    .arg(
                        Arg::new("source-map")
                            .long("source-map")
                            .value_name("FILE")
                            .help("Canonical source map; defaults to ARTIFACT.sourcemap.json for ELF"),
                    )
                    .arg(
                        Arg::new("verify-sources")
                            .long("verify-sources")
                            .action(ArgAction::SetTrue)
                            .help("Also verify metadata source_units against files on disk"),
                    )
                    .arg(
                        Arg::new("json")
                            .long("json")
                            .action(ArgAction::SetTrue)
                            .help("Emit a machine-readable JSON verification summary"),
                    )
                    .arg(
                        Arg::new("expect-target-profile")
                            .long("expect-target-profile")
                            .value_name("PROFILE")
                            .help("Require metadata target_profile to match this value: ckb"),
                    )
                    .arg(
                        Arg::new("expect-artifact-hash")
                            .long("expect-artifact-hash")
                            .value_name("HASH")
                            .help("Require metadata artifact_hash to match this value"),
                    )
                    .arg(
                        Arg::new("expect-source-hash")
                            .long("expect-source-hash")
                            .value_name("HASH")
                            .help("Require metadata source_hash to match this path-bound value"),
                    )
                    .arg(
                        Arg::new("expect-source-content-hash")
                            .long("expect-source-content-hash")
                            .value_name("HASH")
                            .help("Require metadata source_content_hash to match this path-independent value"),
                    )
                    .arg(
                        Arg::new("production")
                            .long("production")
                            .action(ArgAction::SetTrue)
                            .help("Reject fail-closed runtime paths in emitted metadata"),
                    )
                    .arg(
                        Arg::new("deny-fail-closed")
                            .long("deny-fail-closed")
                            .action(ArgAction::SetTrue)
                            .help("Reject metadata that contains fail-closed runtime features or obligations"),
                    )
                    .arg(
                        Arg::new("deny-ckb-runtime")
                            .long("deny-ckb-runtime")
                            .action(ArgAction::SetTrue)
                            .help("Reject CKB transaction/syscall runtime requirements"),
                    )
                    .arg(
                        Arg::new("deny-runtime-obligations")
                            .long("deny-runtime-obligations")
                            .action(ArgAction::SetTrue)
                            .help("Reject runtime-required verifier obligations"),
                    )
                    .arg(
                        Arg::new("primitive-compat")
                            .long("primitive-compat")
                            .value_name("VERSION")
                            .conflicts_with("primitive-strict")
                            .help("Accept primitive syntax from a previous version (e.g. 0.14) with migration hints"),
                    )
                    .arg(
                        Arg::new("primitive-strict")
                            .long("primitive-strict")
                            .value_name("VERSION")
                            .conflicts_with("primitive-compat")
                            .help("Require primitive syntax from a specific version (e.g. 0.15, 0.16, 0.17, or 0.18), reject legacy forms"),
                    ),
            )
            .subcommand(
                ClapCommand::new("run")
                    .about("Experimental: build and run a package")
                    .arg(Arg::new("release").long("release").short('r').action(ArgAction::SetTrue).help("Run in release mode"))

                    .arg(
                        Arg::new("simulate")
                            .long("simulate")
                            .short('s')
                            .action(ArgAction::SetTrue)
                            .help("Simulate execution using AST interpreter instead of ckb-vm"),
                    )
                    .arg(Arg::new("args").value_name("ARGS").num_args(0..).trailing_var_arg(true)),
            )
            .subcommand(
                ClapCommand::new("artifact")
                    .display_order(105)
                    .about("Fetch, verify, pin, copy, and consume non-CellScript Registry artifacts")
                    .subcommand_required(true)
                    .arg_required_else_help(true)
                    .subcommand(
                        ClapCommand::new("ls-idl")
                            .about("Validate, bind, or fetch an exact-byte LS-IDL lock-script interface")
                            .subcommand_required(true)
                            .arg_required_else_help(true)
                            .subcommand(
                                ClapCommand::new("validate")
                                    .about("Validate an LS-IDL 0.1 document and optionally verify its executable suffix")
                                    .arg(Arg::new("idl").long("idl").value_name("FILE").required(true))
                                    .arg(Arg::new("executable").long("executable").value_name("CKB_ELF")),
                            )
                            .subcommand(
                                ClapCommand::new("bind")
                                    .about("Append SHA-256(raw idl.json bytes) to a CKB executable")
                                    .arg(Arg::new("idl").long("idl").value_name("FILE").required(true))
                                    .arg(Arg::new("executable").long("executable").value_name("CKB_ELF").required(true))
                                    .arg(Arg::new("output").long("output").short('o').value_name("CKB_ELF").required(true))
                                    .arg(Arg::new("force").long("force").action(ArgAction::SetTrue)),
                            )
                            .subcommand(
                                ClapCommand::new("fetch")
                                    .about("Fetch exact LS-IDL bytes by a chain-verified CKB script identity")
                                    .arg(Arg::new("code-hash").long("code-hash").value_name("HASH").required(true))
                                    .arg(
                                        Arg::new("hash-type")
                                            .long("hash-type")
                                            .value_name("TYPE")
                                            .value_parser(["data", "data1", "data2", "type"]),
                                    )
                                    .arg(Arg::new("data-hash").long("data-hash").value_name("HASH"))
                                    .arg(
                                        Arg::new("network")
                                            .long("network")
                                            .value_name("NETWORK")
                                            .value_parser(["mainnet", "testnet"])
                                            .default_value("mainnet"),
                                    )
                                    .arg(Arg::new("output").long("output").short('o').value_name("FILE").required(true))
                                    .arg(Arg::new("api-url").long("api-url").value_name("URL"))
                                    .arg(Arg::new("force").long("force").action(ArgAction::SetTrue)),
                            )
                            .subcommand(
                                ClapCommand::new("bundle")
                                    .about("Create a publish-ready LS-IDL Registry bundle and Artifact.toml")
                                    .arg(Arg::new("idl").long("idl").value_name("FILE").required(true))
                                    .arg(Arg::new("executable").long("executable").value_name("CKB_ELF").required(true))
                                    .arg(Arg::new("source").long("source").value_name("FILE").required(true))
                                    .arg(Arg::new("namespace").long("namespace").value_name("NAME").required(true))
                                    .arg(Arg::new("name").long("name").value_name("NAME").required(true))
                                    .arg(Arg::new("release").long("release").value_name("VERSION").required(true))
                                    .arg(
                                        Arg::new("language")
                                            .long("language")
                                            .value_name("LANGUAGE")
                                            .value_parser(["cellscript", "rust", "c", "javascript", "other"])
                                            .required(true),
                                    )
                                    .arg(
                                        Arg::new("hash-type")
                                            .long("hash-type")
                                            .value_name("TYPE")
                                            .value_parser(["data", "data1", "data2", "type"])
                                            .default_value("data1"),
                                    )
                                    .arg(
                                        Arg::new("dep-type")
                                            .long("dep-type")
                                            .value_name("TYPE")
                                            .value_parser(["code", "dep_group"])
                                            .default_value("code"),
                                    )
                                    .arg(Arg::new("toolchain").long("toolchain").value_name("IDENTITY").required(true))
                                    .arg(
                                        Arg::new("source-revision")
                                            .long("source-revision")
                                            .value_name("REVISION")
                                            .required(true),
                                    )
                                    .arg(
                                        Arg::new("output")
                                            .long("output")
                                            .short('o')
                                            .value_name("BUNDLE_JSON")
                                            .default_value("bundle.json"),
                                    )
                                    .arg(
                                        Arg::new("artifact-manifest-output")
                                            .long("artifact-manifest-output")
                                            .value_name("ARTIFACT_TOML")
                                            .default_value("Artifact.toml"),
                                    )
                                    .arg(Arg::new("force").long("force").action(ArgAction::SetTrue)),
                            ),
                    )
                    .subcommand(
                        ClapCommand::new("fetch")
                            .about("Download an immutable artifact bundle and write an authenticated receipt")
                            .arg(Arg::new("coordinate").value_name("NAMESPACE/NAME@RELEASE").required(true))
                            .arg(Arg::new("output").long("output").short('o').value_name("FILE").required(true))
                            .arg(Arg::new("receipt").long("receipt").value_name("FILE"))
                            .arg(Arg::new("api-url").long("api-url").value_name("URL"))
                            .arg(Arg::new("force").long("force").action(ArgAction::SetTrue)),
                    )
                    .subcommand(
                        ClapCommand::new("verify")
                            .about("Verify a downloaded bundle against its signed Registry receipt")
                            .arg(Arg::new("bundle").long("bundle").value_name("FILE").required(true))
                            .arg(Arg::new("receipt").long("receipt").value_name("FILE").required(true)),
                    )
                    .subcommand(
                        ClapCommand::new("pin")
                            .about("Write a deterministic TCB/deployment artifact lock")
                            .arg(Arg::new("coordinate").value_name("NAMESPACE/NAME@RELEASE").required(true))
                            .arg(Arg::new("output").long("output").short('o').value_name("FILE").default_value("Artifacts.lock"))
                            .arg(Arg::new("api-url").long("api-url").value_name("URL"))
                            .arg(
                                Arg::new("accept-hash-bound")
                                    .long("accept-hash-bound")
                                    .action(ArgAction::SetTrue)
                                    .help("Explicitly pin immutable bytes that have integrity evidence but no semantic/security certification"),
                            )
                            .arg(Arg::new("force").long("force").action(ArgAction::SetTrue)),
                    )
                    .subcommand(
                        ClapCommand::new("copy")
                            .about("Materialize an authenticated template file map without overwriting files")
                            .arg(Arg::new("coordinate").value_name("NAMESPACE/NAME@RELEASE").required(true))
                            .arg(Arg::new("destination").long("destination").short('d').value_name("DIR").default_value("."))
                            .arg(Arg::new("api-url").long("api-url").value_name("URL"))
                            .arg(Arg::new("accept-hash-bound").long("accept-hash-bound").action(ArgAction::SetTrue)),
                    )
                    .subcommand(
                        ClapCommand::new("cell-dep")
                            .visible_alias("celldep")
                            .about("Generate a transaction-builder CellDep descriptor from chain-verified deployment evidence")
                            .arg(Arg::new("coordinate").value_name("NAMESPACE/NAME@RELEASE").required(true))
                            .arg(Arg::new("output").long("output").short('o').value_name("FILE").required(true))
                            .arg(Arg::new("api-url").long("api-url").value_name("URL"))
                            .arg(
                                Arg::new("rpc-url")
                                    .long("rpc-url")
                                    .value_name("URL")
                                    .help("Mainnet CKB RPC used to re-check Cell liveness (defaults to CELLSCRIPT_CKB_RPC_URL or mainnet.ckb.dev)"),
                            )
                            .arg(
                                Arg::new("accept-hash-bound")
                                    .long("accept-hash-bound")
                                    .action(ArgAction::SetTrue)
                                    .help("Explicitly consume chain-verified deployment bytes that have integrity evidence but no semantic/security certification"),
                            )
                            .arg(Arg::new("force").long("force").action(ArgAction::SetTrue)),
                    )
                    .subcommand(
                        ClapCommand::new("record-deployment")
                            .about("Sign, submit, and RPC-verify a CKB deployment record")
                            .arg(Arg::new("coordinate").value_name("NAMESPACE/NAME@RELEASE").required(true))
                            .arg(
                                Arg::new("network")
                                    .long("network")
                                    .value_name("NETWORK")
                                    .value_parser(["mainnet", "testnet"])
                                    .default_value("mainnet")
                                    .help("CKB network whose live Cell will be verified; testnet defaults to the isolated Pudge Registry API"),
                            )
                            .arg(Arg::new("code-hash").long("code-hash").value_name("HASH").required(true))
                            .arg(
                                Arg::new("hash-type")
                                    .long("hash-type")
                                    .value_name("TYPE")
                                    .value_parser(["data", "data1", "data2", "type"])
                                    .required(true),
                            )
                            .arg(
                                Arg::new("dep-type")
                                    .long("dep-type")
                                    .value_name("TYPE")
                                    .value_parser(["code", "dep_group"])
                                    .required(true),
                            )
                            .arg(Arg::new("tx-hash").long("tx-hash").value_name("HASH").required(true))
                            .arg(Arg::new("index").long("index").value_name("U32").value_parser(clap::value_parser!(u32)).required(true))
                            .arg(Arg::new("capability-key-id").long("capability-key-id").value_name("KEY_ID").required(true))
                            .arg(Arg::new("capability-signature").long("capability-signature").value_name("SIGNATURE"))
                            .arg(Arg::new("api-url").long("api-url").value_name("URL"))
                            .arg(Arg::new("print-payload").long("print-payload").action(ArgAction::SetTrue)),
                    )
                    .subcommand(
                        ClapCommand::new("set-availability")
                            .about("Set a release active, deprecated, or yanked with a publisher capability")
                            .arg(Arg::new("coordinate").value_name("NAMESPACE/NAME@RELEASE").required(true))
                            .arg(
                                Arg::new("status")
                                    .long("status")
                                    .value_name("STATUS")
                                    .value_parser(["active", "deprecated", "yanked"])
                                    .required(true),
                            )
                            .arg(Arg::new("reason").long("reason").value_name("TEXT"))
                            .arg(Arg::new("capability-key-id").long("capability-key-id").value_name("KEY_ID").required(true))
                            .arg(Arg::new("capability-signature").long("capability-signature").value_name("SIGNATURE"))
                            .arg(Arg::new("api-url").long("api-url").value_name("URL"))
                            .arg(Arg::new("print-payload").long("print-payload").action(ArgAction::SetTrue)),
                    )
                    .subcommand(
                        ClapCommand::new("reproduction-report")
                            .about("Hash a clean reproduction and sign a builder-authenticated report")
                            .arg(Arg::new("coordinate").value_name("NAMESPACE/NAME@RELEASE").required(true))
                            .arg(Arg::new("artifact").long("artifact").value_name("FILE").required(true))
                            .arg(Arg::new("build-log").long("build-log").value_name("FILE").required(true))
                            .arg(Arg::new("builder-id").long("builder-id").value_name("ID").required(true))
                            .arg(Arg::new("trust-domain").long("trust-domain").value_name("DOMAIN").required(true))
                            .arg(Arg::new("builder-key-id").long("builder-key-id").value_name("KEY_ID").required(true))
                            .arg(
                                Arg::new("builder-public-key")
                                    .long("builder-public-key")
                                    .value_name("P256_SPKI")
                                    .required(true),
                            )
                            .arg(Arg::new("output").long("output").short('o').value_name("FILE").required(true))
                            .arg(Arg::new("api-url").long("api-url").value_name("URL"))
                            .arg(Arg::new("force").long("force").action(ArgAction::SetTrue)),
                    )
                    .subcommand(
                        ClapCommand::new("reproduction-evidence")
                            .about("Validate signed independent reproduction reports and generate an admin promotion request")
                            .arg(Arg::new("coordinate").value_name("NAMESPACE/NAME@RELEASE").required(true))
                            .arg(
                                Arg::new("report")
                                    .long("report")
                                    .value_name("FILE")
                                    .action(ArgAction::Append)
                                    .required(true)
                                    .help("Signed independent cellscript-reproduction-report-v2 JSON; pass once per trusted builder"),
                            )
                            .arg(Arg::new("output").long("output").short('o').value_name("FILE").required(true))
                            .arg(Arg::new("api-url").long("api-url").value_name("URL"))
                            .arg(Arg::new("force").long("force").action(ArgAction::SetTrue)),
                    )
                    .subcommand(
                        ClapCommand::new("commitment")
                            .about("Generate the canonical mainnet Registry commitment payload and Cell data")
                            .arg(Arg::new("coordinate").value_name("NAMESPACE/NAME@RELEASE").required(true))
                            .arg(Arg::new("output").long("output").short('o').value_name("FILE").required(true))
                            .arg(Arg::new("api-url").long("api-url").value_name("URL"))
                            .arg(Arg::new("force").long("force").action(ArgAction::SetTrue)),
                    ),
            )
            .subcommand(
                ClapCommand::new("publish")
                    .display_order(110)
                    .about("Publish a package to the public registry, or write an offline fixture with --offline")
                    .arg(
                        Arg::new("dry-run")
                            .long("dry-run")
                            .action(ArgAction::SetTrue)
                            .help("Validate the publish request without submitting it"),
                    )
                    .arg(
                        Arg::new("offline")
                            .long("offline")
                            .action(ArgAction::SetTrue)
                            .help("Write local registry.json fixture metadata instead of using the public write API"),
                    )
                    .arg(
                        Arg::new("allow-dirty")
                            .long("allow-dirty")
                            .action(ArgAction::SetTrue)
                            .help("Allow publishing from a working tree with uncommitted changes"),
                    )
                    .arg(
                        Arg::new("api-url")
                            .long("api-url")
                            .value_name("URL")
                            .help("Registry write API base URL; defaults to CELLSCRIPT_REGISTRY_API_URL or api.registry.cellscript.dev"),
                    )
                    .arg(
                        Arg::new("capability-key-id")
                            .long("capability-key-id")
                            .value_name("KEY_ID")
                            .help("Registry capability key id authorised by a root wallet"),
                    )
                    .arg(
                        Arg::new("authorise")
                            .long("authorise")
                            .action(ArgAction::SetTrue)
                            .conflicts_with_all(["capability-key-id", "capability-signature", "payload", "offline", "dry-run", "print-payload"])
                            .help("Create a short-lived browser wallet session, wait for approval, then continue publishing"),
                    )
                    .arg(
                        Arg::new("no-open")
                            .long("no-open")
                            .action(ArgAction::SetTrue)
                            .requires("authorise")
                            .help("Print the browser authorisation URL without opening it automatically"),
                    )
                    .arg(
                        Arg::new("capability-signature")
                            .long("capability-signature")
                            .value_name("SIGNATURE")
                            .help("P-256 signature over the canonical publish payload"),
                    )
                    .arg(
                        Arg::new("idempotency-key")
                            .long("idempotency-key")
                            .value_name("KEY")
                            .help("Publish retry key; defaults to CELLSCRIPT_REGISTRY_IDEMPOTENCY_KEY or a request hash"),
                    )
                    .arg(
                        Arg::new("payload")
                            .long("payload")
                            .value_name("FILE")
                            .help("Previously generated publish payload JSON to submit with a capability signature"),
                    )
                    .arg(
                        Arg::new("source-snapshot")
                            .long("source-snapshot")
                            .value_name("FILE")
                            .help("Immutable source snapshot bytes to upload; defaults to a generated CellScript source snapshot"),
                    )
                    .arg(
                        Arg::new("artifact-manifest")
                            .long("artifact-manifest")
                            .value_name("FILE")
                            .conflicts_with("offline")
                            .help("Publish a non-package artifact described by Artifact.toml and its immutable bundle"),
                    )
                    .arg(
                        Arg::new("artifact-kind")
                            .long("artifact-kind")
                            .value_name("KIND")
                            .value_parser(["source_library", "profile_library"])
                            .conflicts_with("artifact-manifest")
                            .help("CellScript dependency kind; defaults to source_library"),
                    )
                    .arg(
                        Arg::new("print-payload")
                            .long("print-payload")
                            .action(ArgAction::SetTrue)
                            .help("Print the publish payload and canonical signing bytes without submitting"),
                    )
                    ,
            )
            .subcommand(
                ClapCommand::new("install")
                    .display_order(120)
                    .about("Install a package from registry, git, or path")
                    .arg(Arg::new("crate").value_name("CRATE").help("Registry package name, or namespace/name@version"))
                    .arg(Arg::new("version").long("version").value_name("VERSION").help("Package version constraint to install"))
                    .arg(Arg::new("namespace").long("namespace").value_name("NAMESPACE").help("Package namespace for registry install"))
                    .arg(Arg::new("git").long("git").value_name("URL").help("Install from a git repository URL"))
                    .arg(Arg::new("path").long("path").value_name("PATH").help("Install from a local package path"))
                    .arg(
                        Arg::new("allow-unverified")
                            .long("allow-unverified")
                            .action(ArgAction::SetTrue)
                            .help("Allow direct install of source_published or indexed_pending registry entries"),
                    )
                    .arg(
                        Arg::new("allow-quarantined")
                            .long("allow-quarantined")
                            .action(ArgAction::SetTrue)
                            .help("Allow explicit incident-review install of quarantined registry entries"),
                    ),
            )
            .subcommand(ClapCommand::new("lock").about("Resolve and write the complete Cell.lock dependency graph"))
            .subcommand(ClapCommand::new("update").about("Explicitly repin dependencies and rewrite Cell.lock"))
            .subcommand(
                ClapCommand::new("info")
                    .about("Show package information")
                    ,
            )
            .subcommand(
                ClapCommand::new("login")
                    .hide(true)
                    .about("Experimental: authenticate against a registry")
                    .arg(Arg::new("registry").long("registry").value_name("URL")),
            )
            .subcommand(
                ClapCommand::new("auth")
                    .about("Manage wallet-rooted registry capability authorisation")
                    .subcommand_required(true)
                    .arg_required_else_help(true)
                    .subcommand(
                        ClapCommand::new("login")
                            .hide(true)
                            .about("Create a wallet capability authorisation payload")
                            .arg(
                                Arg::new("registry-origin")
                                    .long("registry-origin")
                                    .value_name("URL")
                                    .help("Registry origin bound into the wallet capability challenge"),
                            )
                            .arg(
                                Arg::new("principal-type")
                                    .long("principal-type")
                                    .value_name("TYPE")
                                    .help("Principal type for the identity binding; defaults to joyid_ckb"),
                            )
                            .arg(
                                Arg::new("principal-id")
                                    .long("principal-id")
                                    .value_name("ID")
                                    .help("Normalized principal binding derived from a supported CCC CKB signer"),
                            )
                            .arg(
                                Arg::new("capability-pubkey")
                                    .long("capability-pubkey")
                                    .value_name("PUBKEY")
                                    .help("Capability public key that will authorise scoped registry requests"),
                            )
                            .arg(
                                Arg::new("scope")
                                    .long("scope")
                                    .value_name("SCOPE")
                                    .action(ArgAction::Append)
                                    .help("Repeatable least-privilege scope: publish, deployment, or availability for namespace/package (or namespace/*)"),
                            )
                            .arg(
                                Arg::new("expires")
                                    .long("expires")
                                    .value_name("DURATION")
                                    .conflicts_with("capability-expires-at")
                                    .help("Capability lifetime, e.g. 90d or 24h"),
                            )
                            .arg(
                                Arg::new("capability-expires-at")
                                    .long("capability-expires-at")
                                    .value_name("TIMESTAMP")
                                    .help("Absolute UTC capability expiry timestamp, e.g. 2026-12-31T00:00:00Z"),
                            )
                            .arg(
                                Arg::new("json")
                                    .long("json")
                                    .action(ArgAction::SetTrue)
                                    .help("Emit the capability authorisation payload as JSON"),
                            ),
                    )
                    .subcommand(
                        ClapCommand::new("capability")
                            .about("Manage scoped publisher capabilities")
                            .subcommand_required(true)
                            .arg_required_else_help(true)
                            .subcommand(
                                ClapCommand::new("create")
                                    .about("Create a wallet capability authorisation payload for CI or local publishing")
                                    .arg(
                                        Arg::new("registry-origin")
                                            .long("registry-origin")
                                            .value_name("URL")
                                            .help("Registry origin bound into the wallet capability challenge"),
                                    )
                                    .arg(
                                        Arg::new("principal-type")
                                            .long("principal-type")
                                            .value_name("TYPE")
                                            .help("Principal type for the identity binding; defaults to joyid_ckb"),
                                    )
                                    .arg(
                                        Arg::new("principal-id")
                                            .long("principal-id")
                                            .value_name("ID")
                                            .help("Normalized principal binding derived from a supported CCC CKB signer"),
                                    )
                                    .arg(
                                        Arg::new("capability-pubkey")
                                            .long("capability-pubkey")
                                            .value_name("PUBKEY")
                                            .help("Capability public key that will authorise scoped registry requests"),
                                    )
                                    .arg(
                                        Arg::new("scope")
                                            .long("scope")
                                            .value_name("SCOPE")
                                            .action(ArgAction::Append)
                                            .help("Repeatable least-privilege scope: publish, deployment, or availability for namespace/package (or namespace/*)"),
                                    )
                                    .arg(
                                        Arg::new("expires")
                                            .long("expires")
                                            .value_name("DURATION")
                                            .conflicts_with("capability-expires-at")
                                            .help("Capability lifetime, e.g. 90d or 24h"),
                                    )
                                    .arg(
                                        Arg::new("capability-expires-at")
                                            .long("capability-expires-at")
                                            .value_name("TIMESTAMP")
                                            .help("Absolute UTC capability expiry timestamp, e.g. 2026-12-31T00:00:00Z"),
                                    )
                                    .arg(
                                        Arg::new("json")
                                            .long("json")
                                            .action(ArgAction::SetTrue)
                                            .help("Emit the capability authorisation payload as JSON"),
                                    ),
                            )
                            .subcommand(
                                ClapCommand::new("submit")
                                    .about("Submit a wallet-signed capability authorisation payload to the registry")
                                    .arg(
                                        Arg::new("api-url")
                                            .long("api-url")
                                            .value_name("URL")
                                            .help("Registry write API base URL; defaults to CELLSCRIPT_REGISTRY_API_URL"),
                                    )
                                    .arg(
                                        Arg::new("payload")
                                            .long("payload")
                                            .value_name("FILE")
                                            .required(true)
                                            .help("Capability authorisation payload JSON created by auth capability create"),
                                    )
                                    .arg(
                                        Arg::new("wallet-signature")
                                            .long("wallet-signature")
                                            .visible_alias("joyid-signature")
                                            .value_name("FILE")
                                            .required(true)
                                            .help("JoyID or CKB wallet signature JSON whose challenge is the canonical payload"),
                                    )
                                    .arg(
                                        Arg::new("json")
                                            .long("json")
                                            .action(ArgAction::SetTrue)
                                            .help("Emit machine-readable capability submission output"),
                                    ),
                            )
                            .subcommand(
                                ClapCommand::new("revoke")
                                    .about("Create or submit a wallet-signed capability revocation payload")
                                    .arg(
                                        Arg::new("api-url")
                                            .long("api-url")
                                            .value_name("URL")
                                            .help("Registry write API base URL; defaults to CELLSCRIPT_REGISTRY_API_URL"),
                                    )
                                    .arg(
                                        Arg::new("registry-origin")
                                            .long("registry-origin")
                                            .value_name("URL")
                                            .help("Registry origin bound into the wallet revocation challenge"),
                                    )
                                    .arg(
                                        Arg::new("principal-type")
                                            .long("principal-type")
                                            .value_name("TYPE")
                                            .help("Principal type for the identity binding; defaults to joyid_ckb"),
                                    )
                                    .arg(
                                        Arg::new("principal-id")
                                            .long("principal-id")
                                            .value_name("ID")
                                            .help("Normalized principal binding derived from a supported CCC CKB signer"),
                                    )
                                    .arg(
                                        Arg::new("capability-key-id")
                                            .long("capability-key-id")
                                            .value_name("KEY_ID")
                                            .help("Capability key id to revoke"),
                                    )
                                    .arg(
                                        Arg::new("payload")
                                            .long("payload")
                                            .value_name("FILE")
                                            .help("Previously generated capability revocation payload JSON"),
                                    )
                                    .arg(
                                        Arg::new("wallet-signature")
                                            .long("wallet-signature")
                                            .visible_alias("joyid-signature")
                                            .value_name("FILE")
                                            .help("JoyID or CKB wallet signature JSON whose challenge is the canonical revoke payload"),
                                    )
                                    .arg(
                                        Arg::new("reason")
                                            .long("reason")
                                            .value_name("TEXT")
                                            .help("Human-readable reason to include with the revocation request"),
                                    )
                                    .arg(
                                        Arg::new("json")
                                            .long("json")
                                            .action(ArgAction::SetTrue)
                                            .help("Emit machine-readable capability revocation output"),
                                    ),
                            ),
                    )
                    .subcommand(
                        ClapCommand::new("reproducer")
                            .about("Manage independent reproducibility builder identities")
                            .subcommand_required(true)
                            .arg_required_else_help(true)
                            .subcommand(
                                ClapCommand::new("create")
                                    .about("Create a P-256 reproducer key and public policy enrollment record")
                                    .arg(
                                        Arg::new("builder-id")
                                            .long("builder-id")
                                            .value_name("ID")
                                            .required(true)
                                            .help("Stable builder identifier assigned by the independent operator"),
                                    )
                                    .arg(
                                        Arg::new("trust-domain")
                                            .long("trust-domain")
                                            .value_name("DOMAIN")
                                            .required(true)
                                            .help("Administrative and private-key custody domain for this builder"),
                                    )
                                    .arg(
                                        Arg::new("private-key-output")
                                            .long("private-key-output")
                                            .value_name("FILE")
                                            .help(
                                                "On Unix, write PKCS#8 base64 to a new mode-0600 file for CI secret enrollment instead of the OS keychain",
                                            ),
                                    )
                                    .arg(
                                        Arg::new("json")
                                            .long("json")
                                            .action(ArgAction::SetTrue)
                                            .help("Emit the public builder enrollment record as JSON without private-key material"),
                                    ),
                            ),
                    )
                    .subcommand(
                        ClapCommand::new("namespace")
                            .about("Manage Registry namespace ownership")
                            .subcommand_required(true)
                            .arg_required_else_help(true)
                            .subcommand(
                                ClapCommand::new("claim")
                                    .about("Claim a namespace with a wallet-signed capability authorisation payload")
                                    .arg(
                                        Arg::new("api-url")
                                            .long("api-url")
                                            .value_name("URL")
                                            .help("Registry write API base URL; defaults to CELLSCRIPT_REGISTRY_API_URL"),
                                    )
                                    .arg(
                                        Arg::new("namespace")
                                            .long("namespace")
                                            .value_name("NAMESPACE")
                                            .required(true)
                                            .help("Namespace to claim; the signed payload must contain a matching publish scope"),
                                    )
                                    .arg(
                                        Arg::new("payload")
                                            .long("payload")
                                            .value_name("FILE")
                                            .required(true)
                                            .help("Capability authorisation payload JSON created by auth capability create"),
                                    )
                                    .arg(
                                        Arg::new("wallet-signature")
                                            .long("wallet-signature")
                                            .visible_alias("joyid-signature")
                                            .value_name("FILE")
                                            .required(true)
                                            .help("JoyID or CKB wallet signature JSON whose challenge is the canonical capability payload"),
                                    )
                                    .arg(
                                        Arg::new("json")
                                            .long("json")
                                            .action(ArgAction::SetTrue)
                                            .help("Emit machine-readable namespace claim output"),
                                    ),
                            ),
                    ),
            )
            .subcommand(
                ClapCommand::new("certify")
                    .display_order(100)
                    .about("Run a deterministic compiler-hosted certification plugin (currently: novaseal-profile-v0)")
                    .arg(
                        Arg::new("plugin")
                            .long("plugin")
                            .value_name("PLUGIN")
                            .required(true)
                            .help("Certification plugin id, e.g. novaseal-profile-v0"),
                    )
                    .arg(
                        Arg::new("repo-root")
                            .long("repo-root")
                            .value_name("DIR")
                            .help("Repository root for Rust certification evidence"),
                    )
                    .arg(
                        Arg::new("report")
                            .long("report")
                            .value_name("JSON")
                            .help("Verify an existing plugin report instead of regenerating it"),
                    )
                    .arg(
                        Arg::new("output")
                            .long("output")
                            .short('o')
                            .value_name("FILE")
                            .help("Write compiler certification report JSON"),
                    )
                    .arg(
                        Arg::new("require-production")
                            .long("require-production")
                            .action(ArgAction::SetTrue)
                            .help("Require external production attestations, not only local profile certification"),
                    )
                    ,
            )
            .subcommand(
                ClapCommand::new("package")
                    .about("Package integrity commands")
                    .subcommand_required(true)
                    .subcommand(ClapCommand::new("lock").about("Resolve and write the complete Cell.lock dependency graph"))
                    .subcommand(ClapCommand::new("verify").about("Verify package integrity against Cell.lock and source tree")),
            )
            .subcommand(
                ClapCommand::new("registry")
                    .display_order(90)
                    .about("Registry integrity commands")
                    .subcommand_required(true)
                    .subcommand(
                        ClapCommand::new("verify")
                            .about("Verify deployment registry records against Cell.lock and chain facts")

                            .arg(Arg::new("live").long("live").action(ArgAction::SetTrue).help("Verify deployment facts with CKB RPC get_live_cell"))
                            .arg(Arg::new("rpc-url").long("rpc-url").value_name("URL").help("CKB RPC URL for --live"))
                            .arg(Arg::new("network").long("network").value_name("NAME").help("Verify only this deployment network with --live"))
                            .arg(
                                Arg::new("require-publisher-signature")
                                    .long("require-publisher-signature")
                                    .action(ArgAction::SetTrue)
                                    .help("Require deployment publisher_signature metadata; cryptographic verification is not yet implemented"),
                            )
                            .arg(
                                Arg::new("require-audit-report")
                                    .long("require-audit-report")
                                    .action(ArgAction::SetTrue)
                                    .help("Require deployment audit_report_hash metadata"),
                            ),
                    )
                    .subcommand(
                        ClapCommand::new("add")
                            .about("Register a new package in the discovery index")
                            .arg(Arg::new("namespace").long("namespace").required(true).value_name("NAMESPACE").help("Package namespace"))
                            .arg(Arg::new("name").long("name").required(true).value_name("NAME").help("Package name"))
                            .arg(Arg::new("source").long("source").required(true).value_name("URL").help("Source repository URL")),
                    )
                    .subcommand(
                        ClapCommand::new("edit")
                            .about("Edit the package registry.json in the current package")
                            .arg(Arg::new("yank").long("yank").value_name("VERSION").help("Mark an existing version as yanked"))
                            .arg(Arg::new("reason").long("reason").value_name("TEXT").help("Reason recorded with --yank"))
                            .arg(Arg::new("replaced-by").long("replaced-by").value_name("VERSION").help("Suggested replacement version recorded with --yank"))
                            .arg(Arg::new("yanked-at").long("yanked-at").value_name("ISO8601").help("Override yank timestamp; defaults to current UTC")),
                    ),
            )
            .subcommand(
                ClapCommand::new("registry-verify")
                    .hide(true)
                    .about("Verify deployment registry records against Cell.lock and chain facts")

                    .arg(Arg::new("live").long("live").action(ArgAction::SetTrue).help("Verify deployment facts with CKB RPC get_live_cell"))
                    .arg(Arg::new("rpc-url").long("rpc-url").value_name("URL").help("CKB RPC URL for --live"))
                    .arg(Arg::new("network").long("network").value_name("NAME").help("Verify only this deployment network with --live"))
                    .arg(
                        Arg::new("require-publisher-signature")
                            .long("require-publisher-signature")
                            .action(ArgAction::SetTrue)
                            .help("Require deployment publisher_signature metadata; cryptographic verification is not yet implemented"),
                    )
                    .arg(
                        Arg::new("require-audit-report")
                            .long("require-audit-report")
                            .action(ArgAction::SetTrue)
                            .help("Require deployment audit_report_hash metadata"),
                    ),
            )
            .subcommand(
                ClapCommand::new("package-verify")
                    .hide(true)
                    .about("Verify package integrity against Cell.lock and source tree")
                    ,
            )
            .subcommand(
                ClapCommand::new("registry-add")
                    .hide(true)
                    .about("Register a new package in the discovery index")
                    .arg(Arg::new("namespace").long("namespace").required(true).value_name("NAMESPACE").help("Package namespace"))
                    .arg(Arg::new("name").long("name").required(true).value_name("NAME").help("Package name"))
                    .arg(Arg::new("source").long("source").required(true).value_name("URL").help("Source repository URL")),
            )
    }

    fn parse_matches(matches: clap::ArgMatches) -> Command {
        match matches.subcommand() {
            Some(("build", m)) => Command::Build(BuildArgs {
                release: m.get_flag("release"),
                target: m.get_one::<String>("target").cloned(),
                target_profile: m.get_one::<String>("target-profile").cloned(),
                entry_action: m.get_one::<String>("entry-action").cloned(),
                entry_lock: m.get_one::<String>("entry-lock").cloned(),
                artifact: m.get_one::<String>("artifact").cloned(),
                jobs: m.get_one::<String>("jobs").and_then(|s| s.parse().ok()),
                features: m.get_many::<String>("features").map(|values| values.cloned().collect()).unwrap_or_default(),
                all_features: m.get_flag("all-features"),
                no_default_features: m.get_flag("no-default-features"),
                locked: m.get_flag("locked"),
                frozen: m.get_flag("frozen"),
                offline: m.get_flag("offline"),
                environment: m.get_one::<String>("environment").cloned(),
                json: json_output(m),
                production: m.get_flag("production"),
                deny_fail_closed: m.get_flag("deny-fail-closed"),
                deny_ckb_runtime: m.get_flag("deny-ckb-runtime"),
                deny_runtime_obligations: m.get_flag("deny-runtime-obligations"),
                primitive_compat: resolve_primitive_compat(
                    m.get_one::<String>("primitive-compat").cloned(),
                    m.get_one::<String>("primitive-strict").cloned(),
                ),
                package: m.get_one::<String>("package").cloned(),
                workspace: m.get_flag("workspace"),
                ..Default::default()
            }),
            Some(("test", m)) => Command::Test(TestArgs {
                filter: m.get_one::<String>("filter").cloned(),
                backend: m.get_one::<String>("backend").cloned(),
                no_run: m.get_flag("no-run"),
                nocapture: m.get_flag("nocapture"),
                fail_fast: m.get_flag("fail-fast"),
                doc: m.get_flag("doc"),
                features: m.get_many::<String>("features").map(|values| values.cloned().collect()).unwrap_or_default(),
                all_features: m.get_flag("all-features"),
                no_default_features: m.get_flag("no-default-features"),
                locked: m.get_flag("locked"),
                frozen: m.get_flag("frozen"),
                offline: m.get_flag("offline"),
                environment: m.get_one::<String>("environment").cloned(),
                json: json_output(m),
                ..Default::default()
            }),
            Some(("doc", m)) => Command::Doc(DocArgs {
                open: m.get_flag("open"),
                json: json_output(m),
                output_format: match m.get_one::<String>("format").map(|s| s.as_str()) {
                    Some("markdown") => OutputFormat::Markdown,
                    Some("json") => OutputFormat::Json,
                    _ => OutputFormat::Html,
                },
                ..Default::default()
            }),
            Some(("fmt", m)) => Command::Fmt(FmtArgs {
                check: m.get_flag("check"),
                json: json_output(m),
                files: m.get_many::<String>("files").map(|v| v.map(PathBuf::from).collect()).unwrap_or_default(),
            }),
            Some(("init", m)) => Command::Init(InitArgs {
                name: m.get_one::<String>("name").cloned(),
                path: m.get_one::<String>("path").map(PathBuf::from),
                lib: m.get_flag("lib"),
                namespace: m.get_one::<String>("namespace").cloned(),
                json: json_output(m),
            }),
            Some(("new", m)) => Command::New(NewArgs {
                name: m.get_one::<String>("name").cloned().expect("required package name"),
                path: m.get_one::<String>("path").map(PathBuf::from),
                lib: m.get_flag("lib"),
                vcs: m.get_one::<String>("vcs").cloned().unwrap_or_else(|| "git".to_string()),
                json: json_output(m),
            }),
            Some(("add", m)) => Command::Add(AddArgs {
                crates: m.get_many::<String>("crates").map(|v| v.cloned().collect()).unwrap_or_default(),
                package: m.get_one::<String>("package-name").cloned(),
                dev: m.get_flag("dev"),
                build: m.get_flag("build"),
                git: m.get_one::<String>("git").cloned(),
                path: m.get_one::<String>("path").map(PathBuf::from),
                use_environment: m.get_one::<String>("use-environment").cloned(),
                environment_independent: m.get_flag("environment-independent"),
                json: json_output(m),
            }),
            Some(("remove", m)) => Command::Remove(RemoveArgs {
                crates: m.get_many::<String>("crates").map(|v| v.cloned().collect()).unwrap_or_default(),
                dev: m.get_flag("dev"),
                build: m.get_flag("build"),
                json: json_output(m),
            }),
            Some(("clean", m)) => Command::Clean(CleanArgs { json: json_output(m), cache: m.get_flag("cache") }),
            Some(("repl", _)) => Command::Repl,
            Some(("check", m)) => Command::Check(CheckArgs {
                all_targets: m.get_flag("all-targets"),
                artifact: m.get_one::<String>("artifact").cloned(),
                target_profile: m.get_one::<String>("target-profile").cloned(),
                json: json_output(m),
                production: m.get_flag("production"),
                deny_fail_closed: m.get_flag("deny-fail-closed"),
                deny_ckb_runtime: m.get_flag("deny-ckb-runtime"),
                deny_runtime_obligations: m.get_flag("deny-runtime-obligations"),
                primitive_compat: resolve_primitive_compat(
                    m.get_one::<String>("primitive-compat").cloned(),
                    m.get_one::<String>("primitive-strict").cloned(),
                ),
                features: m.get_many::<String>("features").map(|values| values.cloned().collect()).unwrap_or_default(),
                all_features: m.get_flag("all-features"),
                no_default_features: m.get_flag("no-default-features"),
                locked: m.get_flag("locked"),
                frozen: m.get_flag("frozen"),
                offline: m.get_flag("offline"),
                environment: m.get_one::<String>("environment").cloned(),
                package: m.get_one::<String>("package").cloned(),
                workspace: m.get_flag("workspace"),
            }),
            Some(("metadata", m)) => Command::Metadata(MetadataArgs {
                input: m.get_one::<String>("input").map(PathBuf::from),
                artifact: m.get_one::<String>("artifact").cloned(),
                output: m.get_one::<String>("output").map(PathBuf::from),
                target: m.get_one::<String>("target").cloned(),
                target_profile: m.get_one::<String>("target-profile").cloned(),
            }),
            Some(("expand", m)) => Command::Expand(ExpandArgs {
                input: m.get_one::<String>("input").map(PathBuf::from),
                artifact: m.get_one::<String>("artifact").cloned(),
                output: m.get_one::<String>("output").map(PathBuf::from),
                target: m.get_one::<String>("target").cloned(),
                target_profile: m.get_one::<String>("target-profile").cloned(),
                json: json_output(m),
            }),
            Some(("migrate", m)) => Command::Migrate(MigrateArgs {
                input: m.get_one::<String>("input").map(PathBuf::from),
                output: m.get_one::<String>("output").map(PathBuf::from),
                to: m.get_one::<String>("to").cloned().unwrap_or_else(|| "2027".to_string()),
                json: json_output(m),
            }),
            Some(("interface", m)) => Command::Interface(InterfaceArgs {
                input: m.get_one::<String>("input").map(PathBuf::from),
                output: m.get_one::<String>("output").map(PathBuf::from),
                target: m.get_one::<String>("target").cloned(),
                target_profile: m.get_one::<String>("target-profile").cloned(),
            }),
            Some(("interface-diff", m)) => Command::InterfaceDiff(InterfaceDiffArgs {
                old: m.get_one::<String>("old").map(PathBuf::from).expect("required old interface"),
                new: m.get_one::<String>("new").map(PathBuf::from).expect("required new interface"),
                output: m.get_one::<String>("output").map(PathBuf::from),
                json: json_output(m),
            }),
            Some(("constraints", m)) => Command::Constraints(ConstraintsArgs {
                input: m.get_one::<String>("input").map(PathBuf::from),
                output: m.get_one::<String>("output").map(PathBuf::from),
                target: m.get_one::<String>("target").cloned(),
                target_profile: m.get_one::<String>("target-profile").cloned(),
                entry_action: m.get_one::<String>("entry-action").cloned(),
                entry_lock: m.get_one::<String>("entry-lock").cloned(),
            }),
            Some(("abi", m)) => Command::Abi(AbiArgs {
                input: m.get_one::<String>("input").map(PathBuf::from),
                output: m.get_one::<String>("output").map(PathBuf::from),
                target: m.get_one::<String>("target").cloned(),
                target_profile: m.get_one::<String>("target-profile").cloned(),
                action: m.get_one::<String>("action").cloned(),
                lock: m.get_one::<String>("lock").cloned(),
            }),
            Some(("scheduler-plan", m)) => Command::SchedulerPlan(SchedulerPlanArgs {
                input: m.get_one::<String>("input").map(PathBuf::from),
                output: m.get_one::<String>("output").map(PathBuf::from),
                target: m.get_one::<String>("target").cloned(),
                target_profile: m.get_one::<String>("target-profile").cloned(),
            }),
            Some(("ckb-hash", m)) => Command::CkbHash(CkbHashArgs {
                input: m.get_one::<String>("input").cloned(),
                hex: m.get_one::<String>("hex").cloned(),
                file: m.get_one::<String>("file").map(PathBuf::from),
                json: json_output(m),
            }),
            Some(("ckb-std-compat", m)) => Command::CkbStdCompat(CkbStdCompatArgs { json: json_output(m) }),
            Some(("explain", m)) => match m.subcommand() {
                Some(("profile", profile)) => Command::ExplainProfile(ExplainProfileArgs {
                    profile: profile.get_one::<String>("profile").cloned().expect("required target profile"),
                    json: json_output(profile),
                }),
                Some(("proof", proof)) => Command::ExplainProof(ExplainProofArgs {
                    input: proof.get_one::<String>("input").map(PathBuf::from),
                    target: proof.get_one::<String>("target").cloned(),
                    target_profile: proof.get_one::<String>("target-profile").cloned(),
                    json: json_output(proof),
                }),
                Some(("assumptions", assumptions)) => Command::ExplainAssumptions(ExplainAssumptionsArgs {
                    input: assumptions.get_one::<String>("input").map(PathBuf::from),
                    target: assumptions.get_one::<String>("target").cloned(),
                    target_profile: assumptions.get_one::<String>("target-profile").cloned(),
                    json: json_output(assumptions),
                }),
                Some(("generics", generics)) => Command::ExplainGenerics(ExplainGenericsArgs {
                    input: generics.get_one::<String>("input").map(PathBuf::from),
                    target: generics.get_one::<String>("target").cloned(),
                    target_profile: generics.get_one::<String>("target-profile").cloned(),
                    json: json_output(generics),
                }),
                Some(("graph", graph)) => Command::ExplainGraph(ExplainGraphArgs {
                    input: graph.get_one::<String>("input").map(PathBuf::from),
                    target: graph.get_one::<String>("target").cloned(),
                    target_profile: graph.get_one::<String>("target-profile").cloned(),
                    json: json_output(graph),
                    format: graph.get_one::<String>("format").cloned(),
                }),
                _ => Command::Explain(ExplainArgs {
                    code: m.get_one::<String>("code").cloned().expect("required runtime error code"),
                    json: json_output(m),
                }),
            },
            Some(("explain-profile", m)) => {
                warn_legacy_alias("explain-profile", "explain profile", json_output(m));
                Command::ExplainProfile(ExplainProfileArgs {
                    profile: m.get_one::<String>("profile").cloned().expect("required target profile"),
                    json: json_output(m),
                })
            }
            Some(("explain-proof", m)) => {
                warn_legacy_alias("explain-proof", "explain proof", json_output(m));
                Command::ExplainProof(ExplainProofArgs {
                    input: m.get_one::<String>("input").map(PathBuf::from),
                    target: m.get_one::<String>("target").cloned(),
                    target_profile: m.get_one::<String>("target-profile").cloned(),
                    json: json_output(m),
                })
            }
            Some(("explain-assumptions", m)) => {
                warn_legacy_alias("explain-assumptions", "explain assumptions", json_output(m));
                Command::ExplainAssumptions(ExplainAssumptionsArgs {
                    input: m.get_one::<String>("input").map(PathBuf::from),
                    target: m.get_one::<String>("target").cloned(),
                    target_profile: m.get_one::<String>("target-profile").cloned(),
                    json: json_output(m),
                })
            }
            Some(("explain-generics", m)) => {
                warn_legacy_alias("explain-generics", "explain generics", json_output(m));
                Command::ExplainGenerics(ExplainGenericsArgs {
                    input: m.get_one::<String>("input").map(PathBuf::from),
                    target: m.get_one::<String>("target").cloned(),
                    target_profile: m.get_one::<String>("target-profile").cloned(),
                    json: json_output(m),
                })
            }
            Some(("explain-graph", m)) => {
                warn_legacy_alias("explain-graph", "explain graph", json_output(m));
                Command::ExplainGraph(ExplainGraphArgs {
                    input: m.get_one::<String>("input").map(PathBuf::from),
                    target: m.get_one::<String>("target").cloned(),
                    target_profile: m.get_one::<String>("target-profile").cloned(),
                    json: json_output(m),
                    format: m.get_one::<String>("format").cloned(),
                })
            }
            Some(("opt-report", m)) => Command::OptReport(OptReportArgs {
                input: m.get_one::<String>("input").map(PathBuf::from),
                output: m.get_one::<String>("output").map(PathBuf::from),
                target: m.get_one::<String>("target").cloned(),
                target_profile: m.get_one::<String>("target-profile").cloned(),
            }),
            Some(("proof-diff", m)) => Command::ProofDiff(ProofDiffArgs {
                old: m.get_one::<String>("old").map(PathBuf::from).expect("required old metadata"),
                new: m.get_one::<String>("new").map(PathBuf::from).expect("required new metadata"),
                json: json_output(m),
            }),
            Some(("profile", m)) => Command::Profile(ProfileArgs {
                input: m.get_one::<String>("input").map(PathBuf::from),
                entry: m.get_one::<String>("entry").cloned(),
                target: m.get_one::<String>("target").cloned(),
                target_profile: m.get_one::<String>("target-profile").cloned(),
                json: json_output(m),
            }),
            Some(("tx", m)) => match m.subcommand() {
                Some(("validate", validate)) => Command::ValidateTx(ValidateTxArgs {
                    against: validate.get_one::<String>("against").map(PathBuf::from).expect("required metadata"),
                    tx: validate.get_one::<String>("tx").map(PathBuf::from).expect("required transaction JSON"),
                    json: json_output(validate),
                }),
                Some(("solve", solve)) => Command::SolveTx(SolveTxArgs {
                    input: solve.get_one::<String>("input").map(PathBuf::from),
                    output: solve.get_one::<String>("output").map(PathBuf::from),
                    target: solve.get_one::<String>("target").cloned(),
                    target_profile: solve.get_one::<String>("target-profile").cloned(),
                    json: json_output(solve),
                }),
                Some(("trace", trace)) => Command::TraceTx(TraceTxArgs {
                    against: trace.get_one::<String>("against").map(PathBuf::from).expect("required metadata"),
                    tx: trace.get_one::<String>("tx").map(PathBuf::from).expect("required transaction JSON"),
                    json: json_output(trace),
                }),
                _ => unreachable!(),
            },
            Some(("trace-tx", m)) => {
                warn_legacy_alias("trace-tx", "tx trace", json_output(m));
                Command::TraceTx(TraceTxArgs {
                    against: m.get_one::<String>("against").map(PathBuf::from).expect("required metadata"),
                    tx: m.get_one::<String>("tx").map(PathBuf::from).expect("required transaction JSON"),
                    json: json_output(m),
                })
            }
            Some(("audit-bundle", m)) => Command::AuditBundle(AuditBundleArgs {
                input: m.get_one::<String>("input").map(PathBuf::from),
                output: m.get_one::<String>("output").map(PathBuf::from),
                target: m.get_one::<String>("target").cloned(),
                target_profile: m.get_one::<String>("target-profile").cloned(),
                json: json_output(m),
            }),
            Some(("validate-tx", m)) => {
                warn_legacy_alias("validate-tx", "tx validate", json_output(m));
                Command::ValidateTx(ValidateTxArgs {
                    against: m.get_one::<String>("against").map(PathBuf::from).expect("required metadata"),
                    tx: m.get_one::<String>("tx").map(PathBuf::from).expect("required transaction JSON"),
                    json: json_output(m),
                })
            }
            Some(("solve-tx", m)) => {
                warn_legacy_alias("solve-tx", "tx solve", json_output(m));
                Command::SolveTx(SolveTxArgs {
                    input: m.get_one::<String>("input").map(PathBuf::from),
                    output: m.get_one::<String>("output").map(PathBuf::from),
                    target: m.get_one::<String>("target").cloned(),
                    target_profile: m.get_one::<String>("target-profile").cloned(),
                    json: json_output(m),
                })
            }
            Some(("verify-ckb-fixtures", m)) => Command::VerifyCkbFixtures(VerifyCkbFixturesArgs {
                manifest: m.get_one::<String>("manifest").map(PathBuf::from).expect("required CKB fixture manifest"),
                json: json_output(m),
            }),
            Some(("deploy", m)) => match m.subcommand() {
                Some(("plan", plan)) => Command::DeployPlan(DeployPlanArgs {
                    input: plan.get_one::<String>("input").map(PathBuf::from),
                    output: plan.get_one::<String>("output").map(PathBuf::from),
                    target: plan.get_one::<String>("target").cloned(),
                    target_profile: plan.get_one::<String>("target-profile").cloned(),
                    json: json_output(plan),
                }),
                Some(("verify", verify)) => Command::VerifyDeploy(VerifyDeployArgs {
                    plan: verify.get_one::<String>("plan").map(PathBuf::from).expect("required deploy plan"),
                    json: json_output(verify),
                }),
                Some(("diff", diff)) => Command::DiffDeploy(DiffDeployArgs {
                    old: diff.get_one::<String>("old").map(PathBuf::from).expect("required old deploy plan"),
                    new: diff.get_one::<String>("new").map(PathBuf::from).expect("required new deploy plan"),
                    json: json_output(diff),
                }),
                Some(("lock-deps", lock_deps)) => Command::LockDeps(LockDepsArgs {
                    input: lock_deps.get_one::<String>("input").map(PathBuf::from),
                    output: lock_deps.get_one::<String>("output").map(PathBuf::from),
                    target: lock_deps.get_one::<String>("target").cloned(),
                    target_profile: lock_deps.get_one::<String>("target-profile").cloned(),
                    json: json_output(lock_deps),
                }),
                _ => unreachable!(),
            },
            Some(("deploy-plan", m)) => {
                warn_legacy_alias("deploy-plan", "deploy plan", json_output(m));
                Command::DeployPlan(DeployPlanArgs {
                    input: m.get_one::<String>("input").map(PathBuf::from),
                    output: m.get_one::<String>("output").map(PathBuf::from),
                    target: m.get_one::<String>("target").cloned(),
                    target_profile: m.get_one::<String>("target-profile").cloned(),
                    json: json_output(m),
                })
            }
            Some(("verify-deploy", m)) => {
                warn_legacy_alias("verify-deploy", "deploy verify", json_output(m));
                Command::VerifyDeploy(VerifyDeployArgs {
                    plan: m.get_one::<String>("plan").map(PathBuf::from).expect("required deploy plan"),
                    json: json_output(m),
                })
            }
            Some(("diff-deploy", m)) => {
                warn_legacy_alias("diff-deploy", "deploy diff", json_output(m));
                Command::DiffDeploy(DiffDeployArgs {
                    old: m.get_one::<String>("old").map(PathBuf::from).expect("required old deploy plan"),
                    new: m.get_one::<String>("new").map(PathBuf::from).expect("required new deploy plan"),
                    json: json_output(m),
                })
            }
            Some(("lock-deps", m)) => {
                warn_legacy_alias("lock-deps", "deploy lock-deps", json_output(m));
                Command::LockDeps(LockDepsArgs {
                    input: m.get_one::<String>("input").map(PathBuf::from),
                    output: m.get_one::<String>("output").map(PathBuf::from),
                    target: m.get_one::<String>("target").cloned(),
                    target_profile: m.get_one::<String>("target-profile").cloned(),
                    json: json_output(m),
                })
            }
            Some(("action", m)) => match m.subcommand() {
                Some(("build", build)) => Command::ActionBuild(ActionBuildArgs {
                    input: build.get_one::<String>("input").map(PathBuf::from),
                    action: build.get_one::<String>("action").cloned(),
                    output: build.get_one::<String>("output").map(PathBuf::from),
                    target: build.get_one::<String>("target").cloned(),
                    target_profile: build.get_one::<String>("target-profile").cloned(),
                    fabric_intent: build.get_flag("fabric-intent"),
                    json: json_output(build),
                }),
                _ => Command::ActionBuild(ActionBuildArgs::default()),
            },
            Some(("gen-builder", m)) => Command::GenBuilder(GenBuilderArgs {
                input: m.get_one::<String>("input").map(PathBuf::from),
                artifact: m.get_one::<String>("artifact").cloned(),
                metadata: m.get_one::<String>("metadata").map(PathBuf::from),
                lockfile: m.get_one::<String>("lockfile").map(PathBuf::from),
                deployed: m.get_one::<String>("deployed").map(PathBuf::from),
                deployment_network: m.get_one::<String>("deployment-network").cloned(),
                action: m.get_one::<String>("action").cloned(),
                output: m.get_one::<String>("output").map(PathBuf::from),
                target: m.get_one::<String>("target").cloned().unwrap_or_else(|| "typescript".to_string()),
                target_profile: m.get_one::<String>("target-profile").cloned(),
                package_name: m.get_one::<String>("package-name").cloned(),
                json: json_output(m),
            }),
            Some(("entry-witness", m)) => Command::EntryWitness(EntryWitnessArgs {
                input: m.get_one::<String>("input").map(PathBuf::from),
                artifact: m.get_one::<String>("artifact").cloned(),
                script_hash: m.get_one::<String>("script-hash").cloned(),
                action: m.get_one::<String>("action").cloned(),
                lock: m.get_one::<String>("lock").cloned(),
                args: m.get_many::<String>("arg").map(|values| values.cloned().collect()).unwrap_or_default(),
                output: m.get_one::<String>("output").map(PathBuf::from),
                target: m.get_one::<String>("target").cloned(),
                target_profile: m.get_one::<String>("target-profile").cloned(),
                json: json_output(m),
            }),
            Some(("receipt", m)) => Command::Receipt(ReceiptArgs {
                input: m.get_one::<String>("input").map(PathBuf::from),
                output: m.get_one::<String>("output").map(PathBuf::from).expect("required output"),
                target: m.get_one::<String>("target").cloned(),
                target_profile: m.get_one::<String>("target-profile").cloned(),
                json: json_output(m),
            }),
            Some(("sign-receipt", m)) => Command::SignReceipt(SignReceiptArgs {
                receipt: m.get_one::<String>("receipt").map(PathBuf::from).expect("required receipt"),
                role: m.get_one::<String>("role").cloned().expect("required role"),
                key: m.get_one::<String>("key").cloned().expect("required key"),
                output: m.get_one::<String>("output").map(PathBuf::from),
                json: json_output(m),
            }),
            Some(("verify-receipt", m)) => Command::VerifyReceipt(VerifyReceiptArgs {
                receipt: m.get_one::<String>("receipt").map(PathBuf::from).expect("required receipt"),
                metadata: m.get_one::<String>("metadata").map(PathBuf::from).expect("required metadata"),
                artifact: m.get_one::<String>("artifact").map(PathBuf::from).expect("required artifact"),
                json: json_output(m),
            }),
            Some(("protocol", protocol)) => match protocol.subcommand() {
                Some(("bundle", bundle)) => match bundle.subcommand() {
                    Some(("check", check)) => Command::ProtocolBundleCheck(ProtocolBundleCheckArgs {
                        manifest: check.get_one::<String>("manifest").map(PathBuf::from).expect("required ProtocolBundle manifest"),
                        output: check.get_one::<String>("output").map(PathBuf::from),
                        json: json_output(check),
                    }),
                    _ => unreachable!(),
                },
                _ => unreachable!(),
            },
            Some(("verify-artifact", m)) => Command::VerifyArtifact(VerifyArtifactArgs {
                artifact: m.get_one::<String>("artifact").map(PathBuf::from).expect("required artifact"),
                metadata: m.get_one::<String>("metadata").map(PathBuf::from),
                lowering_record: m.get_one::<String>("lowering-record").map(PathBuf::from),
                source_map: m.get_one::<String>("source-map").map(PathBuf::from),
                receipt: m.get_one::<String>("receipt").map(PathBuf::from),
                verify_sources: m.get_flag("verify-sources"),
                json: json_output(m),
                expect_target_profile: m.get_one::<String>("expect-target-profile").cloned(),
                expect_artifact_hash: m.get_one::<String>("expect-artifact-hash").cloned(),
                expect_source_hash: m.get_one::<String>("expect-source-hash").cloned(),
                expect_source_content_hash: m.get_one::<String>("expect-source-content-hash").cloned(),
                production: m.get_flag("production"),
                deny_fail_closed: m.get_flag("deny-fail-closed"),
                deny_ckb_runtime: m.get_flag("deny-ckb-runtime"),
                deny_runtime_obligations: m.get_flag("deny-runtime-obligations"),
                primitive_compat: resolve_primitive_compat(
                    m.get_one::<String>("primitive-compat").cloned(),
                    m.get_one::<String>("primitive-strict").cloned(),
                ),
            }),
            Some(("run", m)) => Command::Run(RunArgs {
                args: m.get_many::<String>("args").map(|values| values.cloned().collect()).unwrap_or_default(),
                release: m.get_flag("release"),
                simulate: m.get_flag("simulate"),
                json: json_output(m),
            }),
            Some(("artifact", m)) => Command::Artifact(ArtifactArgs {
                operation: match m.subcommand() {
                    Some(("ls-idl", action)) => match action.subcommand() {
                        Some(("validate", command)) => ArtifactOperation::LsIdlValidate {
                            idl: command.get_one::<String>("idl").map(PathBuf::from).expect("required IDL"),
                            executable: command.get_one::<String>("executable").map(PathBuf::from),
                            json: json_output(command),
                        },
                        Some(("bind", command)) => ArtifactOperation::LsIdlBind {
                            idl: command.get_one::<String>("idl").map(PathBuf::from).expect("required IDL"),
                            executable: command.get_one::<String>("executable").map(PathBuf::from).expect("required executable"),
                            output: command.get_one::<String>("output").map(PathBuf::from).expect("required output"),
                            force: command.get_flag("force"),
                            json: json_output(command),
                        },
                        Some(("fetch", command)) => ArtifactOperation::LsIdlFetch {
                            code_hash: command.get_one::<String>("code-hash").cloned().expect("required code hash"),
                            hash_type: command.get_one::<String>("hash-type").cloned(),
                            data_hash: command.get_one::<String>("data-hash").cloned(),
                            network: command.get_one::<String>("network").cloned().expect("defaulted network"),
                            output: command.get_one::<String>("output").map(PathBuf::from).expect("required output"),
                            api_url: command.get_one::<String>("api-url").cloned(),
                            force: command.get_flag("force"),
                            json: json_output(command),
                        },
                        Some(("bundle", command)) => ArtifactOperation::LsIdlBundle {
                            idl: command.get_one::<String>("idl").map(PathBuf::from).expect("required IDL"),
                            executable: command.get_one::<String>("executable").map(PathBuf::from).expect("required executable"),
                            source: command.get_one::<String>("source").map(PathBuf::from).expect("required source"),
                            namespace: command.get_one::<String>("namespace").cloned().expect("required namespace"),
                            name: command.get_one::<String>("name").cloned().expect("required name"),
                            release: command.get_one::<String>("release").cloned().expect("required release"),
                            language: command.get_one::<String>("language").cloned().expect("required language"),
                            hash_type: command.get_one::<String>("hash-type").cloned().expect("defaulted hash type"),
                            dep_type: command.get_one::<String>("dep-type").cloned().expect("defaulted dep type"),
                            toolchain: command.get_one::<String>("toolchain").cloned().expect("required toolchain"),
                            source_revision: command.get_one::<String>("source-revision").cloned().expect("required source revision"),
                            output: command.get_one::<String>("output").map(PathBuf::from).expect("defaulted output"),
                            artifact_manifest_output: command
                                .get_one::<String>("artifact-manifest-output")
                                .map(PathBuf::from)
                                .expect("defaulted artifact manifest output"),
                            force: command.get_flag("force"),
                            json: json_output(command),
                        },
                        _ => unreachable!(),
                    },
                    Some(("fetch", action)) => ArtifactOperation::Fetch {
                        coordinate: action.get_one::<String>("coordinate").cloned().expect("required coordinate"),
                        output: action.get_one::<String>("output").map(PathBuf::from).expect("required output"),
                        receipt: action.get_one::<String>("receipt").map(PathBuf::from),
                        api_url: action.get_one::<String>("api-url").cloned(),
                        force: action.get_flag("force"),
                        json: json_output(action),
                    },
                    Some(("verify", action)) => ArtifactOperation::Verify {
                        bundle: action.get_one::<String>("bundle").map(PathBuf::from).expect("required bundle"),
                        receipt: action.get_one::<String>("receipt").map(PathBuf::from).expect("required receipt"),
                        json: json_output(action),
                    },
                    Some(("pin", action)) => ArtifactOperation::Pin {
                        coordinate: action.get_one::<String>("coordinate").cloned().expect("required coordinate"),
                        output: action.get_one::<String>("output").map(PathBuf::from).expect("defaulted output"),
                        api_url: action.get_one::<String>("api-url").cloned(),
                        accept_hash_bound: action.get_flag("accept-hash-bound"),
                        force: action.get_flag("force"),
                        json: json_output(action),
                    },
                    Some(("copy", action)) => ArtifactOperation::Copy {
                        coordinate: action.get_one::<String>("coordinate").cloned().expect("required coordinate"),
                        destination: action.get_one::<String>("destination").map(PathBuf::from).expect("defaulted destination"),
                        api_url: action.get_one::<String>("api-url").cloned(),
                        accept_hash_bound: action.get_flag("accept-hash-bound"),
                        json: json_output(action),
                    },
                    Some(("cell-dep", action)) => ArtifactOperation::CellDep {
                        coordinate: action.get_one::<String>("coordinate").cloned().expect("required coordinate"),
                        output: action.get_one::<String>("output").map(PathBuf::from).expect("required output"),
                        api_url: action.get_one::<String>("api-url").cloned(),
                        rpc_url: action.get_one::<String>("rpc-url").cloned(),
                        accept_hash_bound: action.get_flag("accept-hash-bound"),
                        force: action.get_flag("force"),
                        json: json_output(action),
                    },
                    Some(("record-deployment", action)) => ArtifactOperation::RecordDeployment {
                        coordinate: action.get_one::<String>("coordinate").cloned().expect("required coordinate"),
                        network: action.get_one::<String>("network").cloned().expect("defaulted network"),
                        code_hash: action.get_one::<String>("code-hash").cloned().expect("required code hash"),
                        hash_type: action.get_one::<String>("hash-type").cloned().expect("required hash type"),
                        dep_type: action.get_one::<String>("dep-type").cloned().expect("required dep type"),
                        tx_hash: action.get_one::<String>("tx-hash").cloned().expect("required tx hash"),
                        index: *action.get_one::<u32>("index").expect("required index"),
                        capability_key_id: action.get_one::<String>("capability-key-id").cloned().expect("required capability key id"),
                        capability_signature: action.get_one::<String>("capability-signature").cloned(),
                        api_url: action.get_one::<String>("api-url").cloned(),
                        print_payload: action.get_flag("print-payload"),
                        json: json_output(action),
                    },
                    Some(("set-availability", action)) => ArtifactOperation::SetAvailability {
                        coordinate: action.get_one::<String>("coordinate").cloned().expect("required coordinate"),
                        status: action.get_one::<String>("status").cloned().expect("required status"),
                        reason: action.get_one::<String>("reason").cloned(),
                        capability_key_id: action.get_one::<String>("capability-key-id").cloned().expect("required capability key id"),
                        capability_signature: action.get_one::<String>("capability-signature").cloned(),
                        api_url: action.get_one::<String>("api-url").cloned(),
                        print_payload: action.get_flag("print-payload"),
                        json: json_output(action),
                    },
                    Some(("reproduction-report", action)) => ArtifactOperation::ReproductionReport {
                        coordinate: action.get_one::<String>("coordinate").cloned().expect("required coordinate"),
                        artifact: action.get_one::<String>("artifact").map(PathBuf::from).expect("required artifact"),
                        build_log: action.get_one::<String>("build-log").map(PathBuf::from).expect("required build log"),
                        builder_id: action.get_one::<String>("builder-id").cloned().expect("required builder id"),
                        trust_domain: action.get_one::<String>("trust-domain").cloned().expect("required trust domain"),
                        builder_key_id: action.get_one::<String>("builder-key-id").cloned().expect("required builder key id"),
                        builder_public_key: action
                            .get_one::<String>("builder-public-key")
                            .cloned()
                            .expect("required builder public key"),
                        output: action.get_one::<String>("output").map(PathBuf::from).expect("required output"),
                        api_url: action.get_one::<String>("api-url").cloned(),
                        force: action.get_flag("force"),
                        json: json_output(action),
                    },
                    Some(("reproduction-evidence", action)) => ArtifactOperation::ReproductionEvidence {
                        coordinate: action.get_one::<String>("coordinate").cloned().expect("required coordinate"),
                        reports: action
                            .get_many::<String>("report")
                            .expect("required reproduction reports")
                            .map(PathBuf::from)
                            .collect(),
                        output: action.get_one::<String>("output").map(PathBuf::from).expect("required output"),
                        api_url: action.get_one::<String>("api-url").cloned(),
                        force: action.get_flag("force"),
                        json: json_output(action),
                    },
                    Some(("commitment", action)) => ArtifactOperation::Commitment {
                        coordinate: action.get_one::<String>("coordinate").cloned().expect("required coordinate"),
                        output: action.get_one::<String>("output").map(PathBuf::from).expect("required output"),
                        api_url: action.get_one::<String>("api-url").cloned(),
                        force: action.get_flag("force"),
                        json: json_output(action),
                    },
                    _ => unreachable!(),
                },
            }),
            Some(("publish", m)) => Command::Publish(PublishArgs {
                dry_run: m.get_flag("dry-run"),
                offline: m.get_flag("offline"),
                allow_dirty: m.get_flag("allow-dirty"),
                api_url: m.get_one::<String>("api-url").cloned(),
                capability_key_id: m.get_one::<String>("capability-key-id").cloned(),
                authorise: m.get_flag("authorise"),
                no_open: m.get_flag("no-open"),
                capability_signature: m.get_one::<String>("capability-signature").cloned(),
                idempotency_key: m.get_one::<String>("idempotency-key").cloned(),
                payload: m.get_one::<String>("payload").map(PathBuf::from),
                source_snapshot: m.get_one::<String>("source-snapshot").map(PathBuf::from),
                artifact_manifest: m.get_one::<String>("artifact-manifest").map(PathBuf::from),
                artifact_kind: m.get_one::<String>("artifact-kind").cloned(),
                print_payload: m.get_flag("print-payload"),
                json: json_output(m),
            }),
            Some(("install", m)) => Command::Install(InstallArgs {
                crate_name: m.get_one::<String>("crate").cloned(),
                version: m.get_one::<String>("version").cloned(),
                namespace: m.get_one::<String>("namespace").cloned(),
                git: m.get_one::<String>("git").cloned(),
                path: m.get_one::<String>("path").map(PathBuf::from),
                allow_unverified: m.get_flag("allow-unverified"),
                allow_quarantined: m.get_flag("allow-quarantined"),
            }),
            Some(("lock", m)) => Command::Lock(PackageLockArgs { json: json_output(m) }),
            Some(("update", _)) => Command::Update,
            Some(("info", m)) => Command::Info(InfoArgs { json: json_output(m) }),
            Some(("login", m)) => {
                warn_legacy_alias("login", "auth capability create", false);
                Command::Login(LoginArgs { registry: m.get_one::<String>("registry").cloned() })
            }
            Some(("auth", m)) => match m.subcommand() {
                Some(("login", login)) => Command::AuthLogin(auth_capability_args_from_matches(login)),
                Some(("capability", capability)) => match capability.subcommand() {
                    Some(("create", create)) => Command::AuthCapabilityCreate(auth_capability_args_from_matches(create)),
                    Some(("submit", submit)) => Command::AuthCapabilitySubmit(auth_capability_submit_args_from_matches(submit)),
                    Some(("revoke", revoke)) => Command::AuthCapabilityRevoke(auth_capability_revoke_args_from_matches(revoke)),
                    _ => unreachable!(),
                },
                Some(("reproducer", reproducer)) => match reproducer.subcommand() {
                    Some(("create", create)) => Command::AuthReproducerCreate(auth_reproducer_create_args_from_matches(create)),
                    _ => unreachable!(),
                },
                Some(("namespace", namespace)) => match namespace.subcommand() {
                    Some(("claim", claim)) => Command::AuthNamespaceClaim(auth_namespace_claim_args_from_matches(claim)),
                    _ => unreachable!(),
                },
                _ => unreachable!(),
            },
            Some(("certify", m)) => Command::Certify(CertifyArgs {
                plugin: m.get_one::<String>("plugin").cloned().unwrap_or_else(|| NOVASEAL_CERTIFICATION_PLUGIN.to_string()),
                repo_root: m.get_one::<String>("repo-root").map(PathBuf::from),
                report: m.get_one::<String>("report").map(PathBuf::from),
                output: m.get_one::<String>("output").map(PathBuf::from),
                json: json_output(m),
                require_production: m.get_flag("require-production"),
            }),
            Some(("package", m)) => match m.subcommand() {
                Some(("lock", lock)) => Command::Lock(PackageLockArgs { json: json_output(lock) }),
                Some(("verify", verify)) => Command::PackageVerify(PackageVerifyArgs { json: json_output(verify) }),
                _ => unreachable!(),
            },
            Some(("registry", m)) => match m.subcommand() {
                Some(("verify", verify)) => Command::RegistryVerify(RegistryVerifyArgs {
                    json: json_output(verify),
                    live: verify.get_flag("live"),
                    rpc_url: verify.get_one::<String>("rpc-url").cloned(),
                    network: verify.get_one::<String>("network").cloned(),
                    require_publisher_signature: verify.get_flag("require-publisher-signature"),
                    require_audit_report: verify.get_flag("require-audit-report"),
                }),
                Some(("add", add)) => Command::RegistryAdd(RegistryAddArgs {
                    namespace: add.get_one::<String>("namespace").cloned().unwrap_or_default(),
                    name: add.get_one::<String>("name").cloned().unwrap_or_default(),
                    source: add.get_one::<String>("source").cloned().unwrap_or_default(),
                }),
                Some(("edit", edit)) => Command::RegistryEdit(RegistryEditArgs {
                    yank: edit.get_one::<String>("yank").cloned(),
                    reason: edit.get_one::<String>("reason").cloned(),
                    replaced_by: edit.get_one::<String>("replaced-by").cloned(),
                    yanked_at: edit.get_one::<String>("yanked-at").cloned(),
                }),
                _ => unreachable!(),
            },
            Some(("registry-verify", m)) => {
                warn_legacy_alias("registry-verify", "registry verify", json_output(m));
                Command::RegistryVerify(RegistryVerifyArgs {
                    json: json_output(m),
                    live: m.get_flag("live"),
                    rpc_url: m.get_one::<String>("rpc-url").cloned(),
                    network: m.get_one::<String>("network").cloned(),
                    require_publisher_signature: m.get_flag("require-publisher-signature"),
                    require_audit_report: m.get_flag("require-audit-report"),
                })
            }
            Some(("package-verify", m)) => {
                warn_legacy_alias("package-verify", "package verify", json_output(m));
                Command::PackageVerify(PackageVerifyArgs { json: json_output(m) })
            }
            Some(("registry-add", m)) => {
                warn_legacy_alias("registry-add", "registry add", false);
                Command::RegistryAdd(RegistryAddArgs {
                    namespace: m.get_one::<String>("namespace").cloned().unwrap_or_default(),
                    name: m.get_one::<String>("name").cloned().unwrap_or_default(),
                    source: m.get_one::<String>("source").cloned().unwrap_or_default(),
                })
            }
            _ => unreachable!(),
        }
    }
}

/// Resolve --primitive-compat and --primitive-strict into a single version string.
/// --primitive-strict=X takes precedence and sets strict mode.
/// --primitive-compat=X sets compat mode.
fn resolve_primitive_compat(compat: Option<String>, strict: Option<String>) -> Option<String> {
    if strict.is_some() {
        strict
    } else {
        compat
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_artifact_selection_is_explicit_and_preserved_by_build_and_check() {
        let build = CliParser::command().try_get_matches_from(["cellc", "build", "--artifact", "token-policy"]).unwrap();
        let Command::Build(build) = CliParser::parse_matches(build) else {
            panic!("expected build command");
        };
        assert_eq!(build.artifact.as_deref(), Some("token-policy"));
        assert!(build.entry_action.is_none() && build.entry_lock.is_none());
        validate_build_entry_selection(&build).unwrap();

        let check =
            CliParser::command().try_get_matches_from(["cellc", "check", "--artifact", "token-policy", "--all-targets"]).unwrap();
        let Command::Check(check) = CliParser::parse_matches(check) else {
            panic!("expected check command");
        };
        assert_eq!(check.artifact.as_deref(), Some("token-policy"));
        assert!(check.all_targets);

        for command in ["build", "check"] {
            let matches = CliParser::command().try_get_matches_from(["cellc", command]).unwrap();
            match CliParser::parse_matches(matches) {
                Command::Build(args) => assert!(args.artifact.is_none()),
                Command::Check(args) => assert!(args.artifact.is_none()),
                _ => panic!("unexpected command"),
            }
        }
    }

    #[test]
    fn policy_artifact_selection_rejects_mixed_entry_authorities() {
        for flag in ["--entry-action", "--entry-lock"] {
            let error =
                CliParser::command().try_get_matches_from(["cellc", "build", "--artifact", "token-policy", flag, "main"]).unwrap_err();
            assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
        }
        for args in [
            BuildArgs { artifact: Some("token-policy".into()), entry_action: Some("main".into()), ..Default::default() },
            BuildArgs { artifact: Some("token-policy".into()), entry_lock: Some("main".into()), ..Default::default() },
            BuildArgs { entry_action: Some("main".into()), entry_lock: Some("main".into()), ..Default::default() },
        ] {
            assert!(validate_build_entry_selection(&args).unwrap_err().message.contains("mutually exclusive"));
        }
    }

    #[test]
    fn add_dependency_parses_chain_identity_safe_environment_policy() {
        let matches = CliParser::command()
            .try_get_matches_from(["cellc", "add", "peer", "--path", "deps/peer", "--use-environment", "production"])
            .unwrap();
        let Command::Add(args) = CliParser::parse_matches(matches) else {
            panic!("expected add command");
        };
        assert_eq!(args.use_environment.as_deref(), Some("production"));
        assert!(!args.environment_independent);
        let Dependency::Detailed(dependency) = dependency_from_add_args(&args) else {
            panic!("expected detailed dependency");
        };
        assert_eq!(dependency.use_environment.as_deref(), Some("production"));

        let independent = CliParser::command().try_get_matches_from(["cellc", "add", "peer", "--environment-independent"]).unwrap();
        let Command::Add(args) = CliParser::parse_matches(independent) else {
            panic!("expected add command");
        };
        assert!(args.environment_independent);
        assert!(matches!(
            dependency_from_add_args(&args),
            Dependency::Detailed(DetailedDependency { environment_independent: true, .. })
        ));

        let conflict = CliParser::command().try_get_matches_from([
            "cellc",
            "add",
            "peer",
            "--use-environment",
            "production",
            "--environment-independent",
        ]);
        assert_eq!(conflict.unwrap_err().kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn generated_builder_witness_requirement_matches_the_entry_payload_contract() {
        let cases = [
            ("action main() -> u64 { verification return 0 }", false),
            (
                "resource Token has consume { amount: u64 }\n\
                 action main(input token: Token) -> u64 { verification consume token return 0 }",
                false,
            ),
            (
                "shared Config { value: u64 }\n\
                 action main(read config: Config) -> u64 { verification require config.value > 0 return 0 }",
                false,
            ),
            (
                "resource Token has consume { amount: u64 }\n\
                 action main(token: Token) -> u64 { verification consume token return 0 }",
                false,
            ),
            (
                "shared Config { value: u64 }\n\
                 action main(read config: Config, witness expected: u64) -> u64 {\n\
                     verification require config.value == expected return 0\n\
                 }",
                true,
            ),
            // A zero-byte unit still selects the canonical entry payload
            // envelope; testing whether encoding [] fails would miss it.
            ("action main(witness marker: ()) -> u64 { verification return 0 }", true),
        ];
        for edition in [crate::CURRENT_EDITION, crate::NEXT_EDITION] {
            for (declarations, expected) in cases {
                let source = format!("module generated_builder_witness\n{declarations}\n");
                let metadata = crate::compile_metadata(&source, edition, None).expect("builder fixture compiles");
                let action = &metadata.actions[0];
                assert_eq!(action_requires_entry_witness(action), expected, "{edition:?}: {declarations}");
                let contexts = builder_action_error_contexts_json(&[action]);
                assert_eq!(contexts[0]["entry_witness_required"], expected, "error context must agree with payload ABI");
                let manifest = typescript_builder_manifest("@test/bindings", &metadata, &[action], "test-metadata", None, None);
                assert_eq!(manifest["actions"][0]["entry_witness_required"], expected, "builder manifest must agree with payload ABI");
            }
        }
    }

    #[cfg(feature = "vm-runner")]
    #[test]
    fn run_outcome_uses_the_resolved_entry_contract() {
        let metadata = crate::compile_metadata(
            r#"
module selected_entry
lock decoy() -> bool {
    verification
        false
}
action selected(witness value: u64) -> u64 {
    verification
        return value
}
"#,
            crate::CURRENT_EDITION,
            None,
        )
        .unwrap();
        let entry = run_entry_outcome(&metadata).expect("one resolved action entry");
        assert_eq!(entry.kind, "action");
        assert_eq!(entry.name, "selected");
    }

    #[test]
    fn test_command_execution() {
        let _cmd = Command::Clean(CleanArgs::default());
    }

    #[test]
    fn publish_parses_continuous_browser_authorisation() {
        let matches = CliParser::command().try_get_matches_from(["cellc", "publish", "--authorise", "--no-open"]).unwrap();
        let Command::Publish(args) = CliParser::parse_matches(matches) else {
            panic!("expected publish command");
        };
        assert!(args.authorise);
        assert!(args.no_open);
        assert!(args.capability_key_id.is_none());
    }

    #[test]
    fn publish_authorisation_rejects_an_existing_key_override() {
        let result = CliParser::command().try_get_matches_from([
            "cellc",
            "publish",
            "--authorise",
            "--capability-key-id",
            "cap_0123456789abcdef0123456789abcdef",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn browser_authorisation_activates_only_the_server_confirmed_key() {
        for status in ["pending", "cancelled", "expired"] {
            let persisted = std::cell::Cell::new(false);
            activate_registry_key_after_wallet_approval(status, None, "cap_local", || {
                persisted.set(true);
                Ok(())
            })
            .unwrap();
            assert!(!persisted.get(), "{status} must not activate a publishing key");
        }

        for status in ["authorised", "review_pending"] {
            let persisted = std::cell::Cell::new(false);
            activate_registry_key_after_wallet_approval(status, Some("cap_local"), "cap_local", || {
                persisted.set(true);
                Ok(())
            })
            .unwrap();
            assert!(persisted.get(), "{status} must preserve the approved publishing key");
        }

        let persisted = std::cell::Cell::new(false);
        let mismatch = activate_registry_key_after_wallet_approval("authorised", Some("cap_remote"), "cap_local", || {
            persisted.set(true);
            Ok(())
        });
        assert!(mismatch.is_err());
        assert!(!persisted.get(), "a mismatched server key must not be persisted");

        for status in ["authorised", "review_pending"] {
            let activated = std::cell::Cell::new(false);
            let missing = activate_registry_key_after_wallet_approval(status, None, "cap_local", || {
                activated.set(true);
                Ok(())
            });
            assert!(missing.is_err(), "{status} must require a returned key id");
            assert!(!activated.get(), "{status} must not activate a key without its id");
        }
    }

    #[test]
    fn browser_authorisation_removes_pending_keys_only_for_explicit_terminal_failure() {
        for status in ["pending", "authorised", "review_pending", "unreachable", "deadline_elapsed"] {
            assert!(!registry_authorisation_status_removes_pending_key(status), "{status} must preserve the pending key");
        }
        for status in ["cancelled", "expired"] {
            assert!(registry_authorisation_status_removes_pending_key(status), "{status} must remove the pending key");
        }
    }

    #[test]
    fn registry_keychain_state_distinguishes_pending_and_active_keys() {
        let pending = RegistryKeychainSecret {
            schema: REGISTRY_KEYCHAIN_SECRET_SCHEMA.to_string(),
            status: "pending".to_string(),
            pkcs8_b64: "cGVuZGluZw==".to_string(),
            session_id: Some("auth_0123456789abcdef0123456789abcdef".to_string()),
            expires_at: Some("2026-08-05T12:00:00.000Z".to_string()),
            pending_expires_at_unix_seconds: Some(1_786_000_000),
        };
        let encoded = serde_json::to_string(&pending).unwrap();
        let decoded: RegistryKeychainSecret = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded.schema, REGISTRY_KEYCHAIN_SECRET_SCHEMA);
        assert_eq!(decoded.status, "pending");
        assert_eq!(decoded.session_id.as_deref(), Some("auth_0123456789abcdef0123456789abcdef"));

        let active = RegistryKeychainSecret {
            schema: REGISTRY_KEYCHAIN_SECRET_SCHEMA.to_string(),
            status: "active".to_string(),
            pkcs8_b64: pending.pkcs8_b64,
            session_id: None,
            expires_at: None,
            pending_expires_at_unix_seconds: None,
        };
        assert_eq!(serde_json::from_str::<RegistryKeychainSecret>(&serde_json::to_string(&active).unwrap()).unwrap().status, "active");
    }

    #[test]
    fn record_deployment_parses_explicit_testnet_network() {
        let code_hash = format!("0x{}", "11".repeat(32));
        let tx_hash = format!("0x{}", "22".repeat(32));
        let matches = CliParser::command()
            .try_get_matches_from([
                "cellc",
                "artifact",
                "record-deployment",
                "acme/demo@1.0.0",
                "--network",
                "testnet",
                "--code-hash",
                &code_hash,
                "--hash-type",
                "data1",
                "--dep-type",
                "code",
                "--tx-hash",
                &tx_hash,
                "--index",
                "0",
                "--capability-key-id",
                "cap_test",
            ])
            .unwrap();
        let Command::Artifact(ArtifactArgs { operation: ArtifactOperation::RecordDeployment { network, .. } }) =
            CliParser::parse_matches(matches)
        else {
            panic!("expected artifact record-deployment command");
        };
        assert_eq!(network, "testnet");
    }

    #[test]
    fn registry_api_urls_require_https_except_for_loopback() {
        assert_eq!(registry_origin_from_api_base("https://registry.example/api").unwrap(), "https://registry.example");
        assert!(resolve_registry_api_base(Some("http://registry.example".to_string())).is_err());
        assert!(resolve_registry_api_base(Some("http://127.0.0.1:8232".to_string())).is_ok());
        assert!(resolve_registry_api_base(Some("http://[::1]:8232".to_string())).is_ok());
        assert!(resolve_registry_api_base(Some("https://user:secret@registry.example".to_string())).is_err());
        assert!(resolve_registry_api_base(Some("https://registry.example?next=http://internal".to_string())).is_err());
    }

    #[test]
    fn registry_http_client_does_not_follow_redirects() {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 4096];
            let _ = stream.read(&mut request).unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 307 Temporary Redirect\r\nLocation: http://127.0.0.1:9/internal\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
        });

        let response = registry_http_client()
            .unwrap()
            .post(format!("http://{address}/publish"))
            .body("signed metadata")
            .send()
            .expect("redirect response should be returned without following Location");
        assert_eq!(response.status(), reqwest::StatusCode::TEMPORARY_REDIRECT);
        server.join().unwrap();
    }

    #[test]
    fn visible_021_group_arguments_have_help_text() {
        let command = CliParser::command();
        let mut missing = Vec::new();
        for group in ["explain", "auth", "registry", "publish", "install", "tx", "deploy"] {
            let Some(subcommand) = command.get_subcommands().find(|subcommand| subcommand.get_name() == group) else {
                missing.push(format!("cellc {group}: missing command"));
                continue;
            };
            collect_missing_visible_arg_help(&mut missing, &format!("cellc {group}"), subcommand);
        }

        assert!(missing.is_empty(), "visible 0.21 CLI arguments missing help text:\n{}", missing.join("\n"));
    }

    fn collect_missing_visible_arg_help(missing: &mut Vec<String>, path: &str, command: &clap::Command) {
        if command.is_hide_set() {
            return;
        }
        for arg in command.get_arguments().filter(|arg| !arg.is_hide_set()) {
            let help = arg.get_help().map(|help| help.to_string()).unwrap_or_default();
            if help.trim().is_empty() {
                missing.push(format!("{path} {}", arg.get_id()));
            }
        }
        for subcommand in command.get_subcommands() {
            collect_missing_visible_arg_help(missing, &format!("{path} {}", subcommand.get_name()), subcommand);
        }
    }
}
