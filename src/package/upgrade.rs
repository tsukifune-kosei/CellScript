//! Transactional package graph upgrade planning and atomic lockfile apply.

use super::{
    Dependency, DependencyScope, DeployedManifest, DeploymentStatus, LockedBuildInfo, LockedDependency, LockedEnvironment,
    LockedRootGraph, LockedSource, Lockfile, LockfilePackageInfo, PackageManager, PackageManifest, ResolutionOptions,
};
use crate::error::{CompileError, Result};
use crate::{CompileMetadata, CompileOptions, CompileResult};
use camino::Utf8Path;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

pub const UPGRADE_PLAN_SCHEMA: &str = "cellscript-upgrade-plan-v1";
pub const UPGRADE_PLAN_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone)]
pub struct UpgradeOptions {
    pub package: Option<String>,
    pub precise: Option<String>,
    pub scope: DependencyScope,
    pub features: BTreeSet<String>,
    pub all_features: bool,
    pub no_default_features: bool,
    pub environment: Option<String>,
    pub offline: bool,
    pub acknowledgements: BTreeSet<String>,
}

impl Default for UpgradeOptions {
    fn default() -> Self {
        Self {
            package: None,
            precise: None,
            scope: DependencyScope::Test,
            features: BTreeSet::new(),
            all_features: true,
            no_default_features: false,
            environment: None,
            offline: false,
            acknowledgements: BTreeSet::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UpgradeSelection {
    pub package: Option<String>,
    pub precise: Option<String>,
    pub scope: String,
    pub features: Vec<String>,
    pub all_features: bool,
    pub default_features: bool,
    pub environment: Option<String>,
    pub offline: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UpgradeNodeIdentity {
    pub node_id: String,
    pub coordinate: String,
    pub version: String,
    pub source_kind: String,
    pub source_identity: String,
    pub source_hash: Option<String>,
    pub manifest_digest: String,
    pub compiler_requirement: String,
    pub selection_identity: String,
    pub build_evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UpgradeNodeChange {
    pub classification: String,
    pub coordinate: String,
    pub selection_identity: String,
    pub old: Option<UpgradeNodeIdentity>,
    pub new: Option<UpgradeNodeIdentity>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UpgradeEdgeChange {
    pub owner: String,
    pub alias: String,
    pub classification: String,
    pub old_target: Option<String>,
    pub new_target: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpgradeLockTransaction {
    pub member: String,
    pub lock_path: String,
    pub old_lock_sha256: String,
    pub new_lock_sha256: String,
    pub old_lock_content: String,
    pub new_lock_content: String,
    pub old_lock: Lockfile,
    pub new_lock: Lockfile,
    pub node_changes: Vec<UpgradeNodeChange>,
    pub edge_changes: Vec<UpgradeEdgeChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UpgradeCompileEvidence {
    pub status: String,
    pub error: Option<String>,
    pub artifact_hash: Option<String>,
    pub metadata_hash: Option<String>,
    pub interface_hash: Option<String>,
    pub typed_semantics_hash: Option<String>,
    pub compatibility_profile_hash: Option<String>,
    pub target_profile: Option<String>,
    pub vm_abi: Option<String>,
    pub witness_codec: Option<String>,
    pub constraints_hash: Option<String>,
    pub builder_contract_hash: Option<String>,
    pub deployment_contract_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UpgradeDimensionStatus {
    pub dimension: String,
    pub classification: String,
    pub breaking_changes: usize,
    pub compatible_changes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpgradeImpact {
    pub member: String,
    pub environment: Option<String>,
    pub reason: String,
    pub build_unit_schema: String,
    pub old_build_unit_id: Option<String>,
    pub new_build_unit_id: Option<String>,
    pub old_build_unit: Option<crate::package::inspection::BuildUnit>,
    pub new_build_unit: Option<crate::package::inspection::BuildUnit>,
    pub old: UpgradeCompileEvidence,
    pub new: UpgradeCompileEvidence,
    pub interface_report: Option<crate::interface::InterfaceCompatibilityReport>,
    pub dimensions: Vec<UpgradeDimensionStatus>,
    pub typed_semantics: String,
    pub builder_migration: String,
    pub deployment_compatibility: String,
    pub upgrade_authorization: String,
    pub protocol_bundle_inputs: String,
    pub old_protocol_bundle_input_hash: String,
    pub new_protocol_bundle_input_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UpgradePolicyDimension {
    pub dimension: String,
    pub status: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UpgradeDiagnostic {
    pub code: String,
    pub severity: String,
    pub member: Option<String>,
    pub message: String,
    pub acknowledgeable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpgradePlan {
    pub schema: String,
    pub schema_version: u32,
    pub compiler_version: String,
    pub plan_hash: String,
    pub workspace_root: String,
    pub resolve_graph_schema: String,
    pub build_plan_schema: String,
    pub selection: UpgradeSelection,
    pub old_graph_hash: String,
    pub new_graph_hash: String,
    pub locks: Vec<UpgradeLockTransaction>,
    pub reverse_dependents: Vec<UpgradeImpact>,
    pub policy: Vec<UpgradePolicyDimension>,
    pub migration_artifacts_required: Vec<String>,
    pub required_gates: Vec<String>,
    pub diagnostics: Vec<UpgradeDiagnostic>,
    pub required_acknowledgements: Vec<String>,
    pub acknowledgements: Vec<String>,
    pub apply_status: String,
    pub mutates_deployed_manifest: bool,
    pub performs_deployment: bool,
}

#[derive(Debug)]
struct RootCandidate {
    member: String,
    root: PathBuf,
    lock_path: String,
    old_content: String,
    old: Lockfile,
    candidate: Lockfile,
}

#[derive(Debug)]
struct CompiledCandidate {
    evidence: UpgradeCompileEvidence,
    interface: crate::interface::PackageInterface,
    build: LockedBuildInfo,
    compiler_source_hash: Option<String>,
}

pub fn create_upgrade_plan(input: &Path, options: &UpgradeOptions) -> Result<UpgradePlan> {
    if options.precise.is_some() && options.package.is_none() {
        return Err(
            CompileError::without_span("--precise requires --package so the exact update target is reviewable").with_code("E2800")
        );
    }
    if let Some(precise) = options.precise.as_deref() {
        semver::Version::parse(precise).map_err(|error| {
            CompileError::without_span(format!("--precise requires an exact semantic version: {error}")).with_code("E2800")
        })?;
    }

    let workspace_root = find_manifest_root(input)?;
    let roots = package_roots(&workspace_root)?;
    let workspace_mode = roots.len() > 1 || manifest_has_workspace(&workspace_root)?;
    let mut candidates = Vec::with_capacity(roots.len());
    let mut selection_matched = options.package.is_none();
    for root in roots {
        let manager = PackageManager::new(&root);
        let manifest = manager.read_manifest()?;
        let member = manifest.package.name.clone();
        let lock_path = relative_lock_path(&workspace_root, &root)?;
        let old_content = match std::fs::read_to_string(root.join("Cell.lock")) {
            Ok(content) => content,
            Err(error)
                if workspace_mode
                    && error.kind() == std::io::ErrorKind::NotFound
                    && manifest.dependencies.is_empty()
                    && manifest.dev_dependencies.is_empty() =>
            {
                continue;
            }
            Err(error) => {
                return Err(CompileError::without_span(format!(
                    "transactional update requires an existing Cell.lock for member '{}': {error}; run `cellc lock` once",
                    member
                ))
                .with_code("E2800"));
            }
        };
        let old = Lockfile::read_from_root(&root)?.ok_or_else(|| CompileError::without_span("Cell.lock disappeared"))?;
        let (candidate, matched) = resolve_candidate_lock(&root, &manifest, &old, options)?;
        selection_matched |= matched;
        candidates.push(RootCandidate { member, root, lock_path, old_content, old, candidate });
    }
    if !selection_matched {
        return Err(CompileError::without_span(format!(
            "package update selector '{}' did not match a root alias or package coordinate",
            options.package.as_deref().unwrap_or_default()
        ))
        .with_code("E2800"));
    }
    if candidates.is_empty() {
        return Err(CompileError::without_span("no workspace member has an authoritative Cell.lock to update").with_code("E2800"));
    }

    let mut impacts = Vec::new();
    let mut diagnostics = Vec::new();
    let mut required_acknowledgements = BTreeSet::new();
    let mut migration_artifacts = BTreeSet::new();
    let environments = impact_environments(&candidates, options);
    for candidate in &mut candidates {
        let mut primary_build = None;
        let root_environments = environments.get(&candidate.member).cloned().unwrap_or_else(|| vec![None]);
        for environment in root_environments {
            let resolution = resolution_options(options, environment.clone());
            let old_build_unit = inspection_build_unit(&candidate.root, &candidate.old, &resolution).ok();
            let new_build_unit_result = inspection_build_unit(&candidate.root, &candidate.candidate, &resolution);
            let new_build_unit = new_build_unit_result.as_ref().ok().cloned();
            let old_result = compile_against_lock(&candidate.root, &candidate.old, &resolution);
            let new_result = compile_against_lock(&candidate.root, &candidate.candidate, &resolution);
            let mut old_evidence = compile_result_evidence(old_result.as_ref().ok());
            if let Err(error) = &old_result {
                old_evidence.error = Some(error.message.clone());
            }
            let new_compiled = new_result.as_ref().ok().map(compiled_candidate).transpose()?;
            let mut new_evidence =
                new_compiled.as_ref().map(|compiled| compiled.evidence.clone()).unwrap_or_else(|| compile_result_evidence(None));
            if let Err(error) = &new_result {
                new_evidence.error = Some(error.message.clone());
            }
            if primary_build.is_none()
                && let Some(compiled) = new_compiled.as_ref()
            {
                primary_build = Some((compiled.build.clone(), compiled.compiler_source_hash.clone()));
            }
            let old_interface = old_result.as_ref().ok().map(|result| &result.metadata.public_interface);
            let new_interface = new_compiled.as_ref().map(|compiled| &compiled.interface);
            let interface_report = old_interface.zip(new_interface).map(|(old, new)| crate::interface::compare(old, new));
            let dimensions = interface_dimensions(interface_report.as_ref());
            let changed = candidate.old_content != toml::to_string_pretty(&candidate.candidate)?;
            let reason = if changed { "candidate-lock-or-build-identity-changed" } else { "revalidated" };
            let deployed = DeployedManifest::read_from_root(&candidate.root)?;
            let deployment_compatibility = deployment_compatibility(deployed.as_ref(), &old_evidence, &new_evidence);
            let upgrade_authorization = upgrade_authorization(deployed.as_ref(), &deployment_compatibility);
            let builder_migration = identity_change(&old_evidence.builder_contract_hash, &new_evidence.builder_contract_hash);
            let typed_semantics = identity_change(&old_evidence.typed_semantics_hash, &new_evidence.typed_semantics_hash);
            let old_protocol_bundle_input_hash = protocol_bundle_input_hash(&old_evidence)?;
            let new_protocol_bundle_input_hash = protocol_bundle_input_hash(&new_evidence)?;
            let protocol_bundle_inputs =
                if old_protocol_bundle_input_hash != new_protocol_bundle_input_hash { "regeneration-required" } else { "unchanged" }
                    .to_string();

            if let Err(error) = &new_result {
                diagnostics.push(UpgradeDiagnostic {
                    code: "UPG3000".to_string(),
                    severity: "error".to_string(),
                    member: Some(candidate.member.clone()),
                    message: format!("candidate reverse-dependent compilation failed: {}", error.message),
                    acknowledgeable: false,
                });
            }
            if let Err(error) = &new_build_unit_result {
                diagnostics.push(UpgradeDiagnostic {
                    code: "UPG3002".to_string(),
                    severity: "error".to_string(),
                    member: Some(candidate.member.clone()),
                    message: format!("candidate build-unit planning failed: {}", error.message),
                    acknowledgeable: false,
                });
            }
            if old_result.is_err() {
                require_acknowledgement(
                    &mut diagnostics,
                    &mut required_acknowledgements,
                    "UPG3001",
                    &candidate.member,
                    "the old reverse-dependent interface could not be recomputed; review the retained lock build identity and migration evidence",
                );
            }
            if let Some(report) = &interface_report {
                for dimension in report.dimensions.iter().filter(|dimension| dimension.classification == "breaking") {
                    let (code, artifact) = match dimension.dimension.as_str() {
                        "serialized_layout" => ("UPG3102", Some("state-migration-plan")),
                        "runtime_abi" => ("UPG3103", Some("runtime-abi-migration-plan")),
                        "effects_capabilities" => ("UPG3104", Some("capability-review")),
                        "builder" => ("UPG3105", Some("regenerated-builders")),
                        "deployment" => ("UPG3106", Some("deployment-upgrade-plan")),
                        _ => ("UPG3101", None),
                    };
                    if let Some(artifact) = artifact {
                        migration_artifacts.insert(format!("{}:{artifact}", candidate.member));
                    }
                    require_acknowledgement(
                        &mut diagnostics,
                        &mut required_acknowledgements,
                        code,
                        &candidate.member,
                        &format!("{} contains breaking changes", dimension.dimension),
                    );
                }
            } else if old_result.is_ok() && new_result.is_ok() {
                diagnostics.push(UpgradeDiagnostic {
                    code: "UPG3002".to_string(),
                    severity: "error".to_string(),
                    member: Some(candidate.member.clone()),
                    message: "interface evidence was unexpectedly unavailable".to_string(),
                    acknowledgeable: false,
                });
            }
            match upgrade_authorization.as_str() {
                "unauthorized-immutable-deployment" => require_acknowledgement(
                    &mut diagnostics,
                    &mut required_acknowledgements,
                    "UPG4001",
                    &candidate.member,
                    "a deployed artifact changed without a TYPE_ID upgrade authority; the lock update does not authorize deployment",
                ),
                "invalid-type-id-lineage" => require_acknowledgement(
                    &mut diagnostics,
                    &mut required_acknowledgements,
                    "UPG4002",
                    &candidate.member,
                    "TYPE_ID deployment lineage is missing or self-referential; live authorization remains unproven",
                ),
                "external-type-id-proof-required" => require_acknowledgement(
                    &mut diagnostics,
                    &mut required_acknowledgements,
                    "UPG4003",
                    &candidate.member,
                    "TYPE_ID metadata is present, but a live upgrade transaction and authorization proof are still required",
                ),
                _ => {}
            }
            impacts.push(UpgradeImpact {
                member: candidate.member.clone(),
                environment,
                reason: reason.to_string(),
                build_unit_schema: crate::package::inspection::BUILD_PLAN_SCHEMA.to_string(),
                old_build_unit_id: old_build_unit.as_ref().map(|unit| unit.id.clone()),
                new_build_unit_id: new_build_unit.as_ref().map(|unit| unit.id.clone()),
                old_build_unit,
                new_build_unit,
                old: old_evidence,
                new: new_evidence,
                interface_report,
                dimensions,
                typed_semantics,
                builder_migration,
                deployment_compatibility,
                upgrade_authorization,
                protocol_bundle_inputs,
                old_protocol_bundle_input_hash,
                new_protocol_bundle_input_hash,
            });
        }
        if let Some((build, source_hash)) = primary_build {
            candidate.candidate.package_build = Some(build);
            candidate.candidate.package.compiler_source_hash = source_hash;
        } else {
            candidate.candidate.package_build = None;
        }
    }

    let mut locks = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        let new_content = toml::to_string_pretty(&candidate.candidate)?;
        let node_changes = node_changes(&candidate.old, &candidate.candidate)?;
        let edge_changes = edge_changes(&candidate.old, &candidate.candidate);
        classify_node_policy(&candidate.member, &node_changes, &mut diagnostics, &mut required_acknowledgements);
        locks.push(UpgradeLockTransaction {
            member: candidate.member,
            lock_path: candidate.lock_path,
            old_lock_sha256: sha256(candidate.old_content.as_bytes()),
            new_lock_sha256: sha256(new_content.as_bytes()),
            old_lock_content: candidate.old_content,
            new_lock_content: new_content,
            old_lock: candidate.old,
            new_lock: candidate.candidate,
            node_changes,
            edge_changes,
        });
    }
    locks.sort_by(|left, right| left.lock_path.cmp(&right.lock_path));
    impacts.sort_by(|left, right| (&left.member, &left.environment).cmp(&(&right.member, &right.environment)));
    diagnostics.sort_by(|left, right| (&left.code, &left.member, &left.message).cmp(&(&right.code, &right.member, &right.message)));
    diagnostics.dedup_by(|left, right| left.code == right.code && left.member == right.member && left.message == right.message);

    let required_acknowledgements = required_acknowledgements.into_iter().collect::<Vec<_>>();
    let acknowledgements = options.acknowledgements.iter().cloned().collect::<Vec<_>>();
    let missing_acknowledgements =
        required_acknowledgements.iter().filter(|code| !options.acknowledgements.contains(*code)).cloned().collect::<Vec<_>>();
    let hard_blocked = diagnostics.iter().any(|diagnostic| diagnostic.severity == "error" && !diagnostic.acknowledgeable);
    let apply_status = if hard_blocked {
        "blocked"
    } else if missing_acknowledgements.is_empty() {
        "ready"
    } else {
        "requires-acknowledgement"
    }
    .to_string();
    let old_graph_hash = aggregate_graph_hash(&locks, false);
    let new_graph_hash = aggregate_graph_hash(&locks, true);
    let policy = policy_dimensions(&locks, &impacts);
    let mut required_gates = BTreeSet::from(["./scripts/cellscript_gate.sh dev".to_string()]);
    if old_graph_hash != new_graph_hash || impacts.iter().any(|impact| identity_fields_changed(&impact.old, &impact.new)) {
        required_gates.insert("./scripts/cellscript_gate.sh ci".to_string());
    }
    if impacts.iter().any(|impact| impact.deployment_compatibility == "upgrade-required") {
        required_gates.insert("./scripts/cellscript_gate.sh release-quick".to_string());
    }
    let mut plan = UpgradePlan {
        schema: UPGRADE_PLAN_SCHEMA.to_string(),
        schema_version: UPGRADE_PLAN_SCHEMA_VERSION,
        compiler_version: crate::VERSION.to_string(),
        plan_hash: String::new(),
        workspace_root: workspace_root.to_string_lossy().replace('\\', "/"),
        resolve_graph_schema: crate::package::inspection::RESOLVE_GRAPH_SCHEMA.to_string(),
        build_plan_schema: crate::package::inspection::BUILD_PLAN_SCHEMA.to_string(),
        selection: UpgradeSelection {
            package: options.package.clone(),
            precise: options.precise.clone(),
            scope: scope_name(options.scope).to_string(),
            features: options.features.iter().cloned().collect(),
            all_features: options.all_features,
            default_features: !options.no_default_features,
            environment: options.environment.clone(),
            offline: options.offline,
        },
        old_graph_hash,
        new_graph_hash,
        locks,
        reverse_dependents: impacts,
        policy,
        migration_artifacts_required: migration_artifacts.into_iter().collect(),
        required_gates: required_gates.into_iter().collect(),
        diagnostics,
        required_acknowledgements,
        acknowledgements,
        apply_status,
        mutates_deployed_manifest: false,
        performs_deployment: false,
    };
    plan.plan_hash = plan_hash(&plan)?;
    Ok(plan)
}

pub fn apply_upgrade_plan(plan: &UpgradePlan, apply_acknowledgements: &BTreeSet<String>) -> Result<Vec<String>> {
    validate_plan(plan)?;
    let root = std::fs::canonicalize(&plan.workspace_root).map_err(|error| {
        CompileError::without_span(format!("upgrade plan workspace root '{}' is unavailable: {error}", plan.workspace_root))
            .with_code("E2802")
    })?;
    let acknowledgements =
        plan.acknowledgements.iter().cloned().chain(apply_acknowledgements.iter().cloned()).collect::<BTreeSet<_>>();
    let missing = plan.required_acknowledgements.iter().filter(|code| !acknowledgements.contains(*code)).cloned().collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(CompileError::without_span(format!("upgrade plan requires explicit acknowledgement(s): {}", missing.join(", ")))
            .with_code("E2801"));
    }
    if plan.diagnostics.iter().any(|diagnostic| diagnostic.severity == "error" && !diagnostic.acknowledgeable) {
        return Err(CompileError::without_span("upgrade plan contains non-acknowledgeable blocking diagnostics").with_code("E2801"));
    }

    let mut targets = Vec::with_capacity(plan.locks.len());
    let mut planned_paths = BTreeSet::new();
    for transaction in &plan.locks {
        let path = confined_lock_path(&root, &transaction.lock_path)?;
        if !planned_paths.insert(path.clone()) {
            return Err(
                CompileError::without_span(format!("upgrade plan repeats lock path '{}'", transaction.lock_path)).with_code("E2802")
            );
        }
        let current = std::fs::read(&path).map_err(|error| {
            CompileError::without_span(format!("failed to read planned lock '{}': {error}", path.display())).with_code("E2802")
        })?;
        if sha256(&current) != transaction.old_lock_sha256 || current != transaction.old_lock_content.as_bytes() {
            return Err(CompileError::without_span(format!(
                "stale upgrade plan: '{}' no longer matches old lock hash {}",
                transaction.lock_path, transaction.old_lock_sha256
            ))
            .with_code("E2802"));
        }
        if sha256(transaction.new_lock_content.as_bytes()) != transaction.new_lock_sha256 {
            return Err(CompileError::without_span(format!(
                "upgrade plan candidate lock hash is invalid for '{}'",
                transaction.lock_path
            ))
            .with_code("E2802"));
        }
        let parsed: Lockfile = toml::from_str(&transaction.new_lock_content).map_err(|error| {
            CompileError::without_span(format!("upgrade plan candidate lock '{}' is invalid TOML: {error}", transaction.lock_path))
                .with_code("E2802")
        })?;
        parsed.validate_schema()?;
        if toml::to_string_pretty(&parsed)? != transaction.new_lock_content {
            return Err(CompileError::without_span(format!(
                "upgrade plan candidate lock '{}' is not canonical",
                transaction.lock_path
            ))
            .with_code("E2802"));
        }
        targets.push((path, current, transaction.new_lock_content.as_bytes().to_vec()));
    }

    let mut applied = Vec::new();
    for (index, (path, _old, new)) in targets.iter().enumerate() {
        if let Err(error) = atomic_replace(path, new, &format!("{}-{index}", plan.plan_hash.trim_start_matches("sha256:"))) {
            for (rollback_index, (applied_path, applied_old, _)) in targets.iter().take(applied.len()).enumerate().rev() {
                let _ = atomic_replace(applied_path, applied_old, &format!("rollback-{rollback_index}"));
            }
            return Err(error);
        }
        applied.push(path.to_string_lossy().replace('\\', "/"));
    }
    Ok(applied)
}

pub fn read_upgrade_plan(path: &Path) -> Result<UpgradePlan> {
    let bytes = std::fs::read(path).map_err(|error| {
        CompileError::without_span(format!("failed to read upgrade plan '{}': {error}", path.display())).with_code("E2802")
    })?;
    let plan: UpgradePlan = serde_json::from_slice(&bytes).map_err(|error| {
        CompileError::without_span(format!("failed to parse upgrade plan '{}': {error}", path.display())).with_code("E2802")
    })?;
    validate_plan(&plan)?;
    Ok(plan)
}

pub fn validate_plan(plan: &UpgradePlan) -> Result<()> {
    if plan.schema != UPGRADE_PLAN_SCHEMA || plan.schema_version != UPGRADE_PLAN_SCHEMA_VERSION {
        return Err(CompileError::without_span(format!(
            "unsupported upgrade plan schema '{}'/{}; expected '{}'/{}",
            plan.schema, plan.schema_version, UPGRADE_PLAN_SCHEMA, UPGRADE_PLAN_SCHEMA_VERSION
        ))
        .with_code("E2802"));
    }
    if plan.compiler_version != crate::VERSION {
        return Err(CompileError::without_span(format!(
            "upgrade plan compiler '{}' does not match active cellc '{}'",
            plan.compiler_version,
            crate::VERSION
        ))
        .with_code("E2802"));
    }
    if plan.resolve_graph_schema != crate::package::inspection::RESOLVE_GRAPH_SCHEMA
        || plan.build_plan_schema != crate::package::inspection::BUILD_PLAN_SCHEMA
    {
        return Err(CompileError::without_span(format!(
            "upgrade plan graph contracts '{}/{}' do not match active '{}/{}'",
            plan.resolve_graph_schema,
            plan.build_plan_schema,
            crate::package::inspection::RESOLVE_GRAPH_SCHEMA,
            crate::package::inspection::BUILD_PLAN_SCHEMA
        ))
        .with_code("E2802"));
    }
    if plan.mutates_deployed_manifest || plan.performs_deployment {
        return Err(CompileError::without_span("upgrade plan exceeds the lock-only apply boundary").with_code("E2802"));
    }
    let expected = plan_hash(plan)?;
    if plan.plan_hash != expected {
        return Err(CompileError::without_span(format!(
            "upgrade plan hash mismatch: recorded '{}', computed '{}'",
            plan.plan_hash, expected
        ))
        .with_code("E2802"));
    }
    Ok(())
}

fn resolve_candidate_lock(
    root: &Path,
    manifest: &PackageManifest,
    old: &Lockfile,
    options: &UpgradeOptions,
) -> Result<(Lockfile, bool)> {
    let root_selected = options
        .package
        .as_deref()
        .is_some_and(|selector| package_matches(selector, &manifest.package.name, manifest.package.namespace.as_deref()));
    if root_selected && options.precise.is_some() {
        return Err(CompileError::without_span(
            "--precise selects dependency versions; edit the root [package].version in Cell.toml explicitly",
        )
        .with_code("E2800"));
    }
    let mut full = old.clone();
    full.package = lockfile_package_info(root, manifest)?;
    if options.environment.is_none() {
        full.environments.retain(|name, _| manifest.environments.contains_key(name));
        if !manifest.dependency_overrides.is_empty() {
            full.root = LockedRootGraph::default();
        }
    }
    let old_builds = old.dependencies.iter().map(|(id, dependency)| (id.clone(), dependency.clone())).collect::<BTreeMap<_, _>>();
    let mut precise_matched = options.precise.is_none();
    for environment in resolution_environments(manifest, options) {
        let mut resolution_manifest = manifest.clone();
        if let (Some(selector), Some(precise)) = (options.package.as_deref(), options.precise.as_deref()) {
            precise_matched |= exactify_direct_dependency(&mut resolution_manifest, selector, precise)?;
        }
        let resolution = resolution_options(options, environment);
        let mut manager = PackageManager::new(root);
        manager.resolve_dependencies_from_manifest_with_options(&resolution_manifest, &resolution)?;
        full.merge_resolution(&manager, manifest, &resolution)?;
    }
    if !precise_matched {
        return Err(CompileError::without_span(format!(
            "--precise target '{}' must identify a direct dependency alias or coordinate",
            options.package.as_deref().unwrap_or_default()
        ))
        .with_code("E2800"));
    }
    restore_unchanged_build_evidence(&mut full, &old_builds);
    prune_unreachable(&mut full)?;

    let Some(selector) = options.package.as_deref() else {
        return Ok((full, true));
    };
    if root_selected {
        return Ok((full, true));
    }
    let (targeted, matched) = targeted_lock(old, &full, selector)?;
    Ok((targeted, matched))
}

fn targeted_lock(old: &Lockfile, candidate: &Lockfile, selector: &str) -> Result<(Lockfile, bool)> {
    let old_selected = selected_node_ids(old, selector);
    let new_selected = selected_node_ids(candidate, selector);
    if old_selected.is_empty() && new_selected.is_empty() {
        return Ok((old.clone(), false));
    }
    let old_allowed = descendant_coordinates(old, &old_selected);
    let new_allowed = descendant_coordinates(candidate, &new_selected);
    let mut merged = old.clone();
    merged.package = candidate.package.clone();
    merged.root = merge_root_edges(&old.root, &candidate.root, old, candidate, &old_allowed, &new_allowed);
    let environment_names = old.environments.keys().chain(candidate.environments.keys()).cloned().collect::<BTreeSet<_>>();
    merged.environments.clear();
    for name in environment_names {
        match (old.environments.get(&name), candidate.environments.get(&name)) {
            (Some(old_environment), Some(new_environment)) => {
                merged.environments.insert(
                    name,
                    merge_environment_edges(old_environment, new_environment, old, candidate, &old_allowed, &new_allowed),
                );
            }
            (None, Some(environment)) => {
                merged.environments.insert(name, environment.clone());
            }
            (Some(environment), None) => {
                merged.environments.insert(name, environment.clone());
            }
            (None, None) => unreachable!(),
        }
    }

    merged.dependencies.retain(|_, dependency| !old_allowed.contains(&coordinate(dependency)));
    for (node_id, dependency) in &candidate.dependencies {
        if new_allowed.contains(&coordinate(dependency)) {
            merged.dependencies.insert(node_id.clone(), dependency.clone());
        }
    }
    for (node_id, dependency) in &mut merged.dependencies {
        if new_allowed.contains(&coordinate(dependency)) {
            continue;
        }
        let Some(candidate_dependency) = candidate.dependencies.get(node_id) else {
            continue;
        };
        let old_edges = dependency.dependencies.clone();
        for (alias, old_target) in old_edges {
            let old_target_selected =
                old.dependencies.get(&old_target).is_some_and(|target| old_allowed.contains(&coordinate(target)));
            if old_target_selected {
                if let Some(new_target) = candidate_dependency.dependencies.get(&alias) {
                    dependency.dependencies.insert(alias, new_target.clone());
                } else {
                    dependency.dependencies.remove(&alias);
                }
            }
        }
        for (alias, new_target) in &candidate_dependency.dependencies {
            if candidate.dependencies.get(new_target).is_some_and(|target| new_allowed.contains(&coordinate(target))) {
                dependency.dependencies.insert(alias.clone(), new_target.clone());
            }
        }
        if dependency.dependencies != old.dependencies.get(node_id).map(|item| &item.dependencies).cloned().unwrap_or_default() {
            dependency.build = None;
        }
    }
    prune_unreachable(&mut merged)?;
    Ok((merged, true))
}

fn merge_root_edges(
    old: &LockedRootGraph,
    new: &LockedRootGraph,
    old_lock: &Lockfile,
    new_lock: &Lockfile,
    old_allowed: &BTreeSet<(Option<String>, String)>,
    new_allowed: &BTreeSet<(Option<String>, String)>,
) -> LockedRootGraph {
    LockedRootGraph {
        manifest_digest: new.manifest_digest.clone(),
        dependencies: merge_edge_map(&old.dependencies, &new.dependencies, old_lock, new_lock, old_allowed, new_allowed),
        dev_dependencies: merge_edge_map(&old.dev_dependencies, &new.dev_dependencies, old_lock, new_lock, old_allowed, new_allowed),
    }
}

fn merge_environment_edges(
    old: &LockedEnvironment,
    new: &LockedEnvironment,
    old_lock: &Lockfile,
    new_lock: &Lockfile,
    old_allowed: &BTreeSet<(Option<String>, String)>,
    new_allowed: &BTreeSet<(Option<String>, String)>,
) -> LockedEnvironment {
    LockedEnvironment {
        chain_id: new.chain_id.clone(),
        genesis_hash: new.genesis_hash.clone(),
        dependencies: merge_edge_map(&old.dependencies, &new.dependencies, old_lock, new_lock, old_allowed, new_allowed),
        dev_dependencies: merge_edge_map(&old.dev_dependencies, &new.dev_dependencies, old_lock, new_lock, old_allowed, new_allowed),
    }
}

fn merge_edge_map(
    old: &BTreeMap<String, String>,
    new: &BTreeMap<String, String>,
    old_lock: &Lockfile,
    new_lock: &Lockfile,
    old_allowed: &BTreeSet<(Option<String>, String)>,
    new_allowed: &BTreeSet<(Option<String>, String)>,
) -> BTreeMap<String, String> {
    let aliases = old.keys().chain(new.keys()).cloned().collect::<BTreeSet<_>>();
    aliases
        .into_iter()
        .filter_map(|alias| {
            let old_selected = old
                .get(&alias)
                .and_then(|id| old_lock.dependencies.get(id))
                .is_some_and(|dependency| old_allowed.contains(&coordinate(dependency)));
            let new_selected = new
                .get(&alias)
                .and_then(|id| new_lock.dependencies.get(id))
                .is_some_and(|dependency| new_allowed.contains(&coordinate(dependency)));
            let value = if old_selected || new_selected { new.get(&alias) } else { old.get(&alias).or_else(|| new.get(&alias)) };
            value.cloned().map(|value| (alias, value))
        })
        .collect()
}

fn selected_node_ids(lockfile: &Lockfile, selector: &str) -> Vec<String> {
    let mut selected = lockfile
        .dependencies
        .iter()
        .filter(|(_, dependency)| package_matches(selector, &dependency.name, dependency.namespace.as_deref()))
        .map(|(node_id, _)| node_id.clone())
        .collect::<Vec<_>>();
    for edges in all_root_edge_maps(lockfile) {
        if let Some(node_id) = edges.get(selector) {
            selected.push(node_id.clone());
        }
    }
    selected.sort();
    selected.dedup();
    selected
}

fn descendant_coordinates(lockfile: &Lockfile, roots: &[String]) -> BTreeSet<(Option<String>, String)> {
    let mut pending = roots.iter().cloned().collect::<VecDeque<_>>();
    let mut seen = BTreeSet::new();
    let mut coordinates = BTreeSet::new();
    while let Some(node_id) = pending.pop_front() {
        if !seen.insert(node_id.clone()) {
            continue;
        }
        if let Some(dependency) = lockfile.dependencies.get(&node_id) {
            coordinates.insert(coordinate(dependency));
            pending.extend(dependency.dependencies.values().cloned());
        }
    }
    coordinates
}

fn restore_unchanged_build_evidence(candidate: &mut Lockfile, old: &BTreeMap<String, LockedDependency>) {
    for (node_id, dependency) in &mut candidate.dependencies {
        let Some(previous) = old.get(node_id) else { continue };
        if same_locked_source_identity(previous, dependency) {
            dependency.build = previous.build.clone();
        }
    }
}

fn same_locked_source_identity(left: &LockedDependency, right: &LockedDependency) -> bool {
    left.name == right.name
        && left.namespace == right.namespace
        && left.version == right.version
        && serde_json::to_value(&left.source).ok() == serde_json::to_value(&right.source).ok()
        && left.source_hash == right.source_hash
        && left.manifest_digest == right.manifest_digest
        && left.compiler_requirement == right.compiler_requirement
}

fn prune_unreachable(lockfile: &mut Lockfile) -> Result<()> {
    let mut pending = all_root_edge_maps(lockfile).into_iter().flat_map(|edges| edges.values().cloned()).collect::<VecDeque<_>>();
    let mut reachable = BTreeSet::new();
    while let Some(node_id) = pending.pop_front() {
        if !reachable.insert(node_id.clone()) {
            continue;
        }
        let dependency = lockfile.dependencies.get(&node_id).ok_or_else(|| {
            CompileError::without_span(format!("candidate lock edge targets missing node '{node_id}'")).with_code("E2800")
        })?;
        pending.extend(dependency.dependencies.values().cloned());
    }
    lockfile.dependencies.retain(|node_id, _| reachable.contains(node_id));
    lockfile.validate_schema()
}

fn all_root_edge_maps(lockfile: &Lockfile) -> Vec<&BTreeMap<String, String>> {
    let mut maps = vec![&lockfile.root.dependencies, &lockfile.root.dev_dependencies];
    for environment in lockfile.environments.values() {
        maps.push(&environment.dependencies);
        maps.push(&environment.dev_dependencies);
    }
    maps
}

fn compile_against_lock(root: &Path, lockfile: &Lockfile, resolution: &ResolutionOptions) -> Result<CompileResult> {
    let input = Utf8Path::from_path(root)
        .ok_or_else(|| CompileError::without_span(format!("package path '{}' is not valid UTF-8", root.display())))?;
    crate::without_incremental_cache(|| {
        super::with_resolution_options(resolution.clone(), || {
            super::with_lockfile_override(root, lockfile.clone(), || crate::compile_path(input, CompileOptions::default()))
        })
    })
}

fn inspection_build_unit(
    root: &Path,
    lockfile: &Lockfile,
    resolution: &ResolutionOptions,
) -> Result<crate::package::inspection::BuildUnit> {
    super::with_lockfile_override(root, lockfile.clone(), || {
        super::with_resolution_options(resolution.clone(), || {
            let graph = crate::package::inspection::resolve_package_graph(root, resolution)?;
            let mut plan = crate::package::inspection::build_plan(&graph, &crate::package::inspection::BuildPlanOptions::default())?;
            if plan.units.len() != 1 {
                return Err(CompileError::without_span(format!(
                    "upgrade impact expected one package build unit, found {}",
                    plan.units.len()
                )));
            }
            Ok(plan.units.remove(0))
        })
    })
}

fn compiled_candidate(result: &CompileResult) -> Result<CompiledCandidate> {
    Ok(CompiledCandidate {
        evidence: compile_result_evidence(Some(result)),
        interface: result.metadata.public_interface.clone(),
        build: locked_build_info(&result.metadata)?,
        compiler_source_hash: result.metadata.source_hash.clone(),
    })
}

fn compile_result_evidence(result: Option<&CompileResult>) -> UpgradeCompileEvidence {
    let Some(result) = result else {
        return UpgradeCompileEvidence {
            status: "unavailable".to_string(),
            error: None,
            artifact_hash: None,
            metadata_hash: None,
            interface_hash: None,
            typed_semantics_hash: None,
            compatibility_profile_hash: None,
            target_profile: None,
            vm_abi: None,
            witness_codec: None,
            constraints_hash: None,
            builder_contract_hash: None,
            deployment_contract_hash: None,
        };
    };
    let metadata = &result.metadata;
    UpgradeCompileEvidence {
        status: "compiled".to_string(),
        error: None,
        artifact_hash: metadata.artifact_hash.clone(),
        metadata_hash: ckb_hash(metadata).ok(),
        interface_hash: Some(metadata.interface_hash.clone()),
        typed_semantics_hash: Some(metadata.typed_semantics_hash.clone()),
        compatibility_profile_hash: ckb_hash(&metadata.compatibility_profile).ok(),
        target_profile: Some(metadata.target_profile.name.clone()),
        vm_abi: Some(metadata.target_profile.vm_abi.clone()),
        witness_codec: Some(metadata.compatibility_profile.entry_witness_payload_abi.clone()),
        constraints_hash: ckb_hash(&metadata.constraints).ok(),
        builder_contract_hash: Some(metadata.public_interface.builder_contract_hash.clone()),
        deployment_contract_hash: Some(metadata.public_interface.deployment_contract_hash.clone()),
    }
}

fn locked_build_info(metadata: &CompileMetadata) -> Result<LockedBuildInfo> {
    Ok(LockedBuildInfo {
        edition: metadata.edition,
        compatibility_profile_hash: ckb_hash(&metadata.compatibility_profile)?,
        compiler_version: Some(metadata.compiler_version.clone()),
        target_profile: Some(metadata.target_profile.name.clone()),
        artifact_hash: metadata.artifact_hash.clone(),
        metadata_hash: Some(ckb_hash(metadata)?),
        schema_hash: Some(metadata.molecule_schema_manifest.manifest_hash.clone()),
        cell_data_codec_manifest_hash: Some(metadata.cell_data_codec_manifest.manifest_hash.clone()),
        abi_hash: Some(crate::script_handle::compile_metadata_abi_hash(metadata)?),
        constraints_hash: Some(ckb_hash(&metadata.constraints)?),
    })
}

fn interface_dimensions(report: Option<&crate::interface::InterfaceCompatibilityReport>) -> Vec<UpgradeDimensionStatus> {
    const DIMENSIONS: [&str; 6] = ["source_api", "serialized_layout", "runtime_abi", "effects_capabilities", "builder", "deployment"];
    match report {
        Some(report) => report
            .dimensions
            .iter()
            .map(|dimension| UpgradeDimensionStatus {
                dimension: dimension.dimension.clone(),
                classification: dimension.classification.clone(),
                breaking_changes: dimension.breaking_changes,
                compatible_changes: dimension.compatible_changes,
            })
            .collect(),
        None => DIMENSIONS
            .into_iter()
            .map(|dimension| UpgradeDimensionStatus {
                dimension: dimension.to_string(),
                classification: "unknown".to_string(),
                breaking_changes: 0,
                compatible_changes: 0,
            })
            .collect(),
    }
}

fn deployment_compatibility(
    deployed: Option<&DeployedManifest>,
    old: &UpgradeCompileEvidence,
    new: &UpgradeCompileEvidence,
) -> String {
    let Some(deployed) = deployed else { return "not-deployed".to_string() };
    if deployed.deployments.is_empty() {
        return "not-deployed".to_string();
    }
    if old.artifact_hash.is_some() && old.artifact_hash == new.artifact_hash {
        "unchanged".to_string()
    } else {
        "upgrade-required".to_string()
    }
}

fn upgrade_authorization(deployed: Option<&DeployedManifest>, compatibility: &str) -> String {
    let Some(deployed) = deployed else { return "not-applicable".to_string() };
    if compatibility != "upgrade-required" {
        return "not-required".to_string();
    }
    let active = deployed.deployments.iter().filter(|deployment| {
        deployment.status.as_ref().is_none_or(|status| matches!(status, DeploymentStatus::Active | DeploymentStatus::Candidate))
    });
    let mut saw = false;
    for deployment in active {
        saw = true;
        if deployment.type_id.as_deref().is_none_or(str::is_empty) {
            return "unauthorized-immutable-deployment".to_string();
        }
        if deployment
            .upgrade_lineage
            .as_deref()
            .is_none_or(|lineage| lineage.trim().is_empty() || lineage.trim() == deployment.out_point)
        {
            return "invalid-type-id-lineage".to_string();
        }
    }
    if saw {
        "external-type-id-proof-required".to_string()
    } else {
        "not-applicable".to_string()
    }
}

fn node_changes(old: &Lockfile, new: &Lockfile) -> Result<Vec<UpgradeNodeChange>> {
    let old_nodes = indexed_nodes(old)?;
    let new_nodes = indexed_nodes(new)?;
    let keys = old_nodes.keys().chain(new_nodes.keys()).cloned().collect::<BTreeSet<_>>();
    let mut changes = Vec::new();
    let mut unmatched_old = Vec::new();
    let mut unmatched_new = Vec::new();
    for key in keys {
        match (old_nodes.get(&key), new_nodes.get(&key)) {
            (Some(old_node), Some(new_node)) => push_node_change(&mut changes, Some(old_node), Some(new_node)),
            (Some(old_node), None) => unmatched_old.push(old_node),
            (None, Some(new_node)) => unmatched_new.push(new_node),
            (None, None) => unreachable!(),
        }
    }
    let coordinates = unmatched_old
        .iter()
        .map(|node| node.coordinate.clone())
        .chain(unmatched_new.iter().map(|node| node.coordinate.clone()))
        .collect::<BTreeSet<_>>();
    for coordinate in coordinates {
        let mut old_coordinate = unmatched_old.iter().copied().filter(|node| node.coordinate == coordinate).collect::<Vec<_>>();
        let mut new_coordinate = unmatched_new.iter().copied().filter(|node| node.coordinate == coordinate).collect::<Vec<_>>();
        old_coordinate.sort_by(|left, right| left.selection_identity.cmp(&right.selection_identity));
        new_coordinate.sort_by(|left, right| left.selection_identity.cmp(&right.selection_identity));
        let paired = old_coordinate.len().min(new_coordinate.len());
        for index in 0..paired {
            push_node_change(&mut changes, Some(old_coordinate[index]), Some(new_coordinate[index]));
        }
        for old_node in &old_coordinate[paired..] {
            push_node_change(&mut changes, Some(old_node), None);
        }
        for new_node in &new_coordinate[paired..] {
            push_node_change(&mut changes, None, Some(new_node));
        }
    }
    changes.sort_by(|left, right| {
        (&left.coordinate, &left.selection_identity, &left.classification).cmp(&(
            &right.coordinate,
            &right.selection_identity,
            &right.classification,
        ))
    });
    Ok(changes)
}

fn push_node_change(
    changes: &mut Vec<UpgradeNodeChange>,
    old_node: Option<&UpgradeNodeIdentity>,
    new_node: Option<&UpgradeNodeIdentity>,
) {
    if old_node == new_node {
        return;
    }
    let classification = match (old_node, new_node) {
        (None, Some(_)) => "added",
        (Some(_), None) => "removed",
        (Some(old_node), Some(new_node))
            if old_node.source_kind != new_node.source_kind || old_node.source_identity != new_node.source_identity =>
        {
            "source-switched"
        }
        (Some(old_node), Some(new_node)) => {
            match (semver::Version::parse(&old_node.version), semver::Version::parse(&new_node.version)) {
                (Ok(old_version), Ok(new_version)) if new_version > old_version => "upgraded",
                (Ok(old_version), Ok(new_version)) if new_version < old_version => "downgraded",
                _ if old_node.selection_identity != new_node.selection_identity => "feature-environment-changed",
                _ => "content-changed",
            }
        }
        (None, None) => unreachable!(),
    };
    let identity = old_node.or(new_node).expect("one node exists");
    let selection_identity = match (old_node, new_node) {
        (Some(old), Some(new)) if old.selection_identity != new.selection_identity => {
            format!("{} -> {}", old.selection_identity, new.selection_identity)
        }
        _ => identity.selection_identity.clone(),
    };
    changes.push(UpgradeNodeChange {
        classification: classification.to_string(),
        coordinate: identity.coordinate.clone(),
        selection_identity,
        old: old_node.cloned(),
        new: new_node.cloned(),
    });
}

fn indexed_nodes(lockfile: &Lockfile) -> Result<BTreeMap<String, UpgradeNodeIdentity>> {
    lockfile
        .dependencies
        .iter()
        .map(|(node_id, dependency)| {
            let identity = node_identity(node_id, dependency)?;
            let key = format!("{}|{}", identity.coordinate, identity.selection_identity);
            Ok((key, identity))
        })
        .collect()
}

fn node_identity(node_id: &str, dependency: &LockedDependency) -> Result<UpgradeNodeIdentity> {
    let selection_identity = node_id
        .split_once("|compiler=")
        .map(|(_, suffix)| format!("compiler={suffix}"))
        .ok_or_else(|| CompileError::without_span(format!("lock node '{node_id}' has no selection identity")))?;
    let (source_kind, source_identity) = locked_source_identity(&dependency.source);
    Ok(UpgradeNodeIdentity {
        node_id: node_id.to_string(),
        coordinate: display_coordinate(&coordinate(dependency)),
        version: dependency.version.clone(),
        source_kind,
        source_identity,
        source_hash: dependency.source_hash.clone(),
        manifest_digest: dependency.manifest_digest.clone(),
        compiler_requirement: dependency.compiler_requirement.clone(),
        selection_identity,
        build_evidence: if dependency.build.is_some() { "preserved" } else { "recompute-required" }.to_string(),
    })
}

fn edge_changes(old: &Lockfile, new: &Lockfile) -> Vec<UpgradeEdgeChange> {
    let old_edges = flattened_edges(old);
    let new_edges = flattened_edges(new);
    let keys = old_edges.keys().chain(new_edges.keys()).cloned().collect::<BTreeSet<_>>();
    keys.into_iter()
        .filter_map(|key| {
            let old_target = old_edges.get(&key).cloned();
            let new_target = new_edges.get(&key).cloned();
            if old_target == new_target {
                return None;
            }
            let (owner, alias) = key.split_once('\0').expect("internal edge key");
            let classification = match (&old_target, &new_target) {
                (None, Some(_)) => "added",
                (Some(_), None) => "removed",
                _ => "retargeted",
            };
            Some(UpgradeEdgeChange {
                owner: owner.to_string(),
                alias: alias.to_string(),
                classification: classification.to_string(),
                old_target,
                new_target,
            })
        })
        .collect()
}

fn flattened_edges(lockfile: &Lockfile) -> BTreeMap<String, String> {
    let mut edges = BTreeMap::new();
    insert_edges(&mut edges, "root:runtime", &lockfile.root.dependencies);
    insert_edges(&mut edges, "root:test", &lockfile.root.dev_dependencies);
    for (environment, graph) in &lockfile.environments {
        insert_edges(&mut edges, &format!("environment:{environment}:runtime"), &graph.dependencies);
        insert_edges(&mut edges, &format!("environment:{environment}:test"), &graph.dev_dependencies);
    }
    for (node_id, dependency) in &lockfile.dependencies {
        insert_edges(&mut edges, &format!("node:{node_id}"), &dependency.dependencies);
    }
    edges
}

fn insert_edges(target: &mut BTreeMap<String, String>, owner: &str, edges: &BTreeMap<String, String>) {
    for (alias, node_id) in edges {
        target.insert(format!("{owner}\0{alias}"), node_id.clone());
    }
}

fn classify_node_policy(
    member: &str,
    changes: &[UpgradeNodeChange],
    diagnostics: &mut Vec<UpgradeDiagnostic>,
    acknowledgements: &mut BTreeSet<String>,
) {
    for change in changes {
        let (code, message) = match change.classification.as_str() {
            "downgraded" => ("UPG2001", format!("{} is downgraded", change.coordinate)),
            "source-switched" => ("UPG2002", format!("{} changes source authority or immutable source identity", change.coordinate)),
            "feature-environment-changed" => ("UPG2003", format!("{} changes feature or environment selection", change.coordinate)),
            _ => continue,
        };
        require_acknowledgement(diagnostics, acknowledgements, code, member, &message);
    }
}

fn require_acknowledgement(
    diagnostics: &mut Vec<UpgradeDiagnostic>,
    acknowledgements: &mut BTreeSet<String>,
    code: &str,
    member: &str,
    message: &str,
) {
    acknowledgements.insert(code.to_string());
    diagnostics.push(UpgradeDiagnostic {
        code: code.to_string(),
        severity: "warning".to_string(),
        member: Some(member.to_string()),
        message: message.to_string(),
        acknowledgeable: true,
    });
}

fn policy_dimensions(locks: &[UpgradeLockTransaction], impacts: &[UpgradeImpact]) -> Vec<UpgradePolicyDimension> {
    let mut source_evidence = Vec::new();
    for transaction in locks {
        source_evidence.extend(
            transaction
                .node_changes
                .iter()
                .map(|change| format!("{}:{}:{}", transaction.member, change.coordinate, change.classification)),
        );
    }
    let dimension = |name: &str| {
        let evidence = impacts
            .iter()
            .flat_map(|impact| {
                impact
                    .dimensions
                    .iter()
                    .filter(move |dimension| dimension.dimension == name)
                    .map(|dimension| format!("{}:{}", impact.member, dimension.classification))
            })
            .collect::<Vec<_>>();
        let status = if evidence.iter().any(|item| item.ends_with(":breaking")) {
            "breaking"
        } else if evidence.iter().any(|item| item.ends_with(":unknown")) {
            "unknown"
        } else {
            "compatible"
        };
        UpgradePolicyDimension { dimension: name.to_string(), status: status.to_string(), evidence }
    };
    let mut policy = vec![UpgradePolicyDimension {
        dimension: "source_semver".to_string(),
        status: if locks
            .iter()
            .flat_map(|transaction| &transaction.node_changes)
            .any(|change| matches!(change.classification.as_str(), "downgraded" | "source-switched"))
        {
            "review-required"
        } else {
            "accepted"
        }
        .to_string(),
        evidence: source_evidence,
    }];
    policy.extend(
        ["source_api", "serialized_layout", "runtime_abi", "effects_capabilities", "builder", "deployment"].into_iter().map(dimension),
    );
    policy.push(UpgradePolicyDimension {
        dimension: "upgrade_authorization".to_string(),
        status: if impacts
            .iter()
            .any(|impact| impact.upgrade_authorization.contains("unauthorized") || impact.upgrade_authorization.contains("invalid"))
        {
            "unproven"
        } else if impacts.iter().any(|impact| impact.upgrade_authorization == "external-type-id-proof-required") {
            "external-proof-required"
        } else {
            "not-required"
        }
        .to_string(),
        evidence: impacts.iter().map(|impact| format!("{}:{}", impact.member, impact.upgrade_authorization)).collect(),
    });
    policy
}

fn exactify_direct_dependency(manifest: &mut PackageManifest, selector: &str, precise: &str) -> Result<bool> {
    let mut matched = exactify_dependency_table(&mut manifest.dependencies, selector, precise)?;
    matched |= exactify_dependency_table(&mut manifest.dev_dependencies, selector, precise)?;
    for dependencies in manifest.dependency_overrides.values_mut() {
        matched |= exactify_dependency_table(dependencies, selector, precise)?;
    }
    Ok(matched)
}

fn exactify_dependency_table<'a, T>(dependencies: T, selector: &str, precise: &str) -> Result<bool>
where
    T: IntoIterator<Item = (&'a String, &'a mut Dependency)>,
{
    let mut matched = false;
    for (alias, dependency) in dependencies {
        let package_name = dependency_package_name(alias, dependency);
        let namespace = dependency_namespace(dependency);
        if alias == selector || package_matches(selector, package_name, namespace) {
            set_exact_version(alias, dependency, precise)?;
            matched = true;
        }
    }
    Ok(matched)
}

fn set_exact_version(alias: &str, dependency: &mut Dependency, precise: &str) -> Result<()> {
    match dependency {
        Dependency::Simple(version) => {
            ensure_precise_satisfies(alias, version, precise)?;
            *version = format!("={precise}");
        }
        Dependency::Detailed(detail) => {
            if detail.path.is_some() || detail.git.is_some() {
                return Err(CompileError::without_span(format!(
                    "--precise cannot replace the immutable path or git source selected by dependency '{alias}'"
                ))
                .with_code("E2800"));
            }
            ensure_precise_satisfies(alias, &detail.version, precise)?;
            detail.version = format!("={precise}");
        }
    }
    Ok(())
}

fn ensure_precise_satisfies(alias: &str, requirement: &str, precise: &str) -> Result<()> {
    let requirement = super::version::parse_version_req(requirement)?;
    if !super::version::satisfies(precise, &requirement) {
        return Err(CompileError::without_span(format!("--precise version '{precise}' is outside dependency '{alias}' requirement"))
            .with_code("E2800"));
    }
    Ok(())
}

fn dependency_package_name<'a>(alias: &'a str, dependency: &'a Dependency) -> &'a str {
    match dependency {
        Dependency::Simple(_) => alias,
        Dependency::Detailed(detail) => detail.package.as_deref().unwrap_or(alias),
    }
}

fn dependency_namespace(dependency: &Dependency) -> Option<&str> {
    match dependency {
        Dependency::Simple(_) => None,
        Dependency::Detailed(detail) => detail.namespace.as_deref(),
    }
}

fn resolution_options(options: &UpgradeOptions, environment: Option<String>) -> ResolutionOptions {
    ResolutionOptions {
        scope: options.scope,
        features: options.features.clone(),
        all_features: options.all_features,
        no_default_features: options.no_default_features,
        environment,
        offline: options.offline,
    }
}

fn resolution_environments(manifest: &PackageManifest, options: &UpgradeOptions) -> Vec<Option<String>> {
    if let Some(environment) = options.environment.as_ref() {
        return vec![Some(environment.clone())];
    }
    let mut environments = Vec::new();
    if manifest.dependency_overrides.is_empty() {
        environments.push(None);
    }
    environments.extend(manifest.environments.keys().cloned().map(Some));
    if environments.is_empty() {
        environments.push(None);
    }
    environments
}

fn impact_environments(candidates: &[RootCandidate], options: &UpgradeOptions) -> BTreeMap<String, Vec<Option<String>>> {
    candidates
        .iter()
        .map(|candidate| {
            let manifest = PackageManager::new(&candidate.root).read_manifest().expect("candidate manifest already validated");
            (candidate.member.clone(), resolution_environments(&manifest, options))
        })
        .collect()
}

fn lockfile_package_info(root: &Path, manifest: &PackageManifest) -> Result<LockfilePackageInfo> {
    Ok(LockfilePackageInfo {
        edition: manifest.package.edition,
        name: manifest.package.name.clone(),
        version: manifest.package.version.clone(),
        namespace: manifest.package.namespace.clone(),
        source_hash: Some(super::registry::compute_source_hash(root)?),
        compiler_source_hash: None,
        compiler_requirement: manifest.package.cellscript_version.clone(),
        resolver_compiler_version: crate::VERSION.to_string(),
    })
}

fn package_roots(root: &Path) -> Result<Vec<PathBuf>> {
    let source = std::fs::read_to_string(root.join("Cell.toml"))?;
    let document: toml::Value = toml::from_str(&source)?;
    if document.get("workspace").is_some() {
        let mut roots = super::workspace::resolve_workspace_member_paths(root)?;
        if document.get("package").is_some() {
            roots.push(std::fs::canonicalize(root)?);
        }
        roots.sort();
        roots.dedup();
        Ok(roots)
    } else {
        Ok(vec![root.to_path_buf()])
    }
}

fn manifest_has_workspace(root: &Path) -> Result<bool> {
    let source = std::fs::read_to_string(root.join("Cell.toml"))?;
    let document: toml::Value = toml::from_str(&source)?;
    Ok(document.get("workspace").is_some())
}

fn find_manifest_root(input: &Path) -> Result<PathBuf> {
    let input = if input.as_os_str().is_empty() { Path::new(".") } else { input };
    let canonical = std::fs::canonicalize(input)
        .map_err(|error| CompileError::without_span(format!("failed to canonicalize update input '{}': {error}", input.display())))?;
    let mut cursor = if canonical.is_dir() { canonical } else { canonical.parent().unwrap_or(&canonical).to_path_buf() };
    loop {
        if cursor.join("Cell.toml").is_file() {
            return Ok(cursor);
        }
        if !cursor.pop() {
            return Err(CompileError::without_span("update input is not inside a CellScript package or workspace"));
        }
    }
}

fn relative_lock_path(workspace_root: &Path, package_root: &Path) -> Result<String> {
    let relative =
        package_root.strip_prefix(workspace_root).map_err(|_| CompileError::without_span("package root escaped workspace"))?;
    let path = relative.join("Cell.lock").to_string_lossy().replace('\\', "/");
    Ok(if path == "Cell.lock" { path } else { path.trim_start_matches("./").to_string() })
}

fn confined_lock_path(root: &Path, relative: &str) -> Result<PathBuf> {
    let path = Path::new(relative);
    if path.is_absolute()
        || path.components().any(|component| !matches!(component, Component::Normal(_)))
        || path.file_name().and_then(|name| name.to_str()) != Some("Cell.lock")
    {
        return Err(CompileError::without_span(format!("upgrade plan lock path '{relative}' is not confined")).with_code("E2802"));
    }
    let target = root.join(path);
    let parent = std::fs::canonicalize(target.parent().unwrap_or(root))
        .map_err(|error| CompileError::without_span(format!("upgrade plan lock parent is unavailable: {error}")).with_code("E2802"))?;
    if !parent.starts_with(root) {
        return Err(
            CompileError::without_span(format!("upgrade plan lock path '{relative}' escapes the workspace")).with_code("E2802")
        );
    }
    if std::fs::symlink_metadata(&target).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err(CompileError::without_span(format!("upgrade plan refuses symlink lock path '{relative}'")).with_code("E2802"));
    }
    Ok(target)
}

fn atomic_replace(path: &Path, content: &[u8], suffix: &str) -> Result<()> {
    let parent = path.parent().ok_or_else(|| CompileError::without_span("lockfile has no parent directory"))?;
    let temporary = parent.join(format!(".Cell.lock.cellscript-update-{suffix}.tmp"));
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&temporary).map_err(|error| {
        CompileError::without_span(format!("failed to create atomic lockfile temporary '{}': {error}", temporary.display()))
    })?;
    if let Err(error) = file.write_all(content).and_then(|_| file.sync_all()) {
        let _ = std::fs::remove_file(&temporary);
        return Err(CompileError::without_span(format!(
            "failed to write atomic lockfile temporary '{}': {error}",
            temporary.display()
        )));
    }
    drop(file);
    if let Err(error) = std::fs::rename(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(CompileError::without_span(format!("failed to atomically replace '{}': {error}", path.display())));
    }
    if let Ok(directory) = std::fs::File::open(parent) {
        let _ = directory.sync_all();
    }
    Ok(())
}

fn plan_hash(plan: &UpgradePlan) -> Result<String> {
    let mut value = serde_json::to_value(plan)?;
    value["plan_hash"] = serde_json::Value::String(String::new());
    Ok(sha256(&serde_json::to_vec(&value)?))
}

fn aggregate_graph_hash(locks: &[UpgradeLockTransaction], new: bool) -> String {
    let values = locks
        .iter()
        .map(|transaction| {
            if new {
                (&transaction.lock_path, &transaction.new_lock_sha256)
            } else {
                (&transaction.lock_path, &transaction.old_lock_sha256)
            }
        })
        .collect::<Vec<_>>();
    sha256(&serde_json::to_vec(&values).expect("lock graph hash is serializable"))
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn ckb_hash<T: Serialize>(value: &T) -> Result<String> {
    let bytes = serde_json::to_vec(value)?;
    Ok(crate::hex_encode(&crate::ckb_blake2b256(&bytes)))
}

fn coordinate(dependency: &LockedDependency) -> (Option<String>, String) {
    (dependency.namespace.clone(), dependency.name.clone())
}

fn display_coordinate(coordinate: &(Option<String>, String)) -> String {
    coordinate.0.as_deref().map_or_else(|| coordinate.1.clone(), |namespace| format!("{namespace}/{}", coordinate.1))
}

fn package_matches(selector: &str, name: &str, namespace: Option<&str>) -> bool {
    selector == name || namespace.is_some_and(|namespace| selector == format!("{namespace}/{name}"))
}

fn locked_source_identity(source: &LockedSource) -> (String, String) {
    match source {
        LockedSource::Path { path } => ("path".to_string(), path.clone()),
        LockedSource::Git { url, revision } => ("git".to_string(), format!("{url}#{revision}")),
        LockedSource::Registry { registry, url, revision, namespace, version } => {
            ("registry".to_string(), format!("{registry}:{namespace}@{version}#{revision}:{url}"))
        }
    }
}

fn identity_change(old: &Option<String>, new: &Option<String>) -> String {
    match (old, new) {
        (Some(old), Some(new)) if old == new => "unchanged",
        (Some(_), Some(_)) => "required",
        _ => "unknown",
    }
    .to_string()
}

fn identity_fields_changed(old: &UpgradeCompileEvidence, new: &UpgradeCompileEvidence) -> bool {
    old.artifact_hash != new.artifact_hash
        || old.metadata_hash != new.metadata_hash
        || old.interface_hash != new.interface_hash
        || old.typed_semantics_hash != new.typed_semantics_hash
        || old.builder_contract_hash != new.builder_contract_hash
        || old.deployment_contract_hash != new.deployment_contract_hash
}

fn protocol_bundle_input_hash(evidence: &UpgradeCompileEvidence) -> Result<String> {
    let value = serde_json::json!({
        "interface_hash": evidence.interface_hash,
        "typed_semantics_hash": evidence.typed_semantics_hash,
        "compatibility_profile_hash": evidence.compatibility_profile_hash,
        "target_profile": evidence.target_profile,
        "vm_abi": evidence.vm_abi,
        "witness_codec": evidence.witness_codec,
        "constraints_hash": evidence.constraints_hash,
        "builder_contract_hash": evidence.builder_contract_hash,
        "deployment_contract_hash": evidence.deployment_contract_hash,
    });
    Ok(sha256(&serde_json::to_vec(&value)?))
}

fn scope_name(scope: DependencyScope) -> &'static str {
    match scope {
        DependencyScope::Runtime => "runtime",
        DependencyScope::Test => "test",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dependency(name: &str, version: &str, path: &str) -> LockedDependency {
        LockedDependency {
            name: name.to_string(),
            namespace: None,
            version: version.to_string(),
            source: LockedSource::Path { path: path.to_string() },
            source_hash: Some(format!("hash-{version}")),
            manifest_digest: format!("manifest-{version}"),
            compiler_requirement: "*".to_string(),
            resolver_compiler_version: crate::VERSION.to_string(),
            dependencies: BTreeMap::new(),
            build: None,
        }
    }

    #[test]
    fn node_diff_classifies_downgrade_and_source_substitution_independently() {
        let mut old = Lockfile::new();
        let mut new = Lockfile::new();
        let suffix = "|compiler=2a|env=default|features=default";
        let old_id = format!("dep@2.0.0|path:old{suffix}");
        let new_id = format!("dep@1.0.0|path:new{suffix}");
        old.dependencies.insert(old_id.clone(), dependency("dep", "2.0.0", "old"));
        new.dependencies.insert(new_id.clone(), dependency("dep", "1.0.0", "new"));
        old.root.dependencies.insert("dep".to_string(), old_id);
        new.root.dependencies.insert("dep".to_string(), new_id);
        let changes = node_changes(&old, &new).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].classification, "source-switched");

        new.dependencies.values_mut().next().unwrap().source = LockedSource::Path { path: "old".to_string() };
        let changes = node_changes(&old, &new).unwrap();
        assert_eq!(changes[0].classification, "downgraded");
    }

    #[test]
    fn node_diff_classifies_feature_or_environment_selection_changes() {
        let mut old = Lockfile::new();
        let mut new = Lockfile::new();
        let old_id = "dep@1.0.0|path:same|compiler=2a|env=default|features=default".to_string();
        let new_id = "dep@1.0.0|path:same|compiler=2a|env=testnet|features=default,proofs".to_string();
        old.dependencies.insert(old_id.clone(), dependency("dep", "1.0.0", "same"));
        new.dependencies.insert(new_id.clone(), dependency("dep", "1.0.0", "same"));
        old.root.dependencies.insert("dep".to_string(), old_id);
        new.root.dependencies.insert("dep".to_string(), new_id);

        let changes = node_changes(&old, &new).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].classification, "feature-environment-changed");
        assert!(changes[0].selection_identity.contains(" -> "));
    }

    #[test]
    fn interface_dimensions_keep_layout_builder_and_profile_breaks_separate() {
        let mut old = crate::interface::PackageInterface {
            module: "demo".to_string(),
            module_identity: "demo".to_string(),
            builder_contract_hash: "builder-old".to_string(),
            deployment_contract_hash: "deploy-old".to_string(),
            runtime_contract: crate::interface::InterfaceRuntimeContract {
                target_profile: "ckb".to_string(),
                ..crate::interface::InterfaceRuntimeContract::default()
            },
            ..crate::interface::PackageInterface::default()
        };
        old.types.push(crate::interface::InterfaceType {
            identity: "demo::State".to_string(),
            name: "State".to_string(),
            kind: "resource".to_string(),
            visibility: "public".to_string(),
            type_parameters: Vec::new(),
            value_abilities: Vec::new(),
            cell_capabilities: Vec::new(),
            fields: vec![crate::interface::InterfaceField {
                name: "value".to_string(),
                r#type: "u64".to_string(),
                offset: Some(0),
                encoded_size: Some(8),
            }],
            variants: Vec::new(),
            layout_identity: "layout-old".to_string(),
            type_identity: None,
        });
        let mut new = old.clone();
        new.builder_contract_hash = "builder-new".to_string();
        new.deployment_contract_hash = "deploy-new".to_string();
        new.runtime_contract.target_profile = "ckb-vm2".to_string();
        new.types[0].fields[0].r#type = "u128".to_string();
        new.types[0].fields[0].encoded_size = Some(16);
        new.types[0].layout_identity = "layout-new".to_string();
        let report = crate::interface::compare(&old, &new);
        let dimensions = interface_dimensions(Some(&report));
        assert_eq!(dimensions.iter().find(|item| item.dimension == "runtime_abi").unwrap().classification, "breaking");
        assert_eq!(dimensions.iter().find(|item| item.dimension == "serialized_layout").unwrap().classification, "breaking");
        assert_eq!(dimensions.iter().find(|item| item.dimension == "builder").unwrap().classification, "breaking");
        assert_eq!(dimensions.iter().find(|item| item.dimension == "deployment").unwrap().classification, "breaking");
    }

    #[test]
    fn deployment_authorization_never_treats_type_id_metadata_as_a_live_proof() {
        let mut deployed = DeployedManifest {
            version: DeployedManifest::CURRENT_VERSION,
            schema: super::super::DEPLOYED_MANIFEST_SCHEMA.to_string(),
            package: super::super::DeployedPackageInfo {
                name: "demo".to_string(),
                version: "1.0.0".to_string(),
                edition: crate::CURRENT_EDITION,
                source_hash: None,
            },
            build: None,
            deployments: Vec::new(),
        };
        let mut record = super::super::DeploymentRecord {
            edition: crate::CURRENT_EDITION,
            network: "testnet".to_string(),
            chain_id: "ckb-testnet".to_string(),
            tx_hash: format!("0x{}", "11".repeat(32)),
            output_index: 0,
            code_hash: format!("0x{}", "22".repeat(32)),
            hash_type: "type".to_string(),
            dep_type: "code".to_string(),
            data_hash: format!("0x{}", "33".repeat(32)),
            out_point: format!("0x{}:0", "11".repeat(32)),
            artifact_hash: None,
            metadata_hash: None,
            schema_hash: None,
            cell_data_codec_manifest_hash: None,
            abi_hash: None,
            constraints_hash: None,
            compiler_version: None,
            compatibility_profile_hash: "profile".to_string(),
            type_id: None,
            script_role: None,
            status: Some(DeploymentStatus::Active),
            upgrade_lineage: None,
            audit_report_hash: None,
            publisher_signature: None,
            cell_deps: Vec::new(),
        };
        deployed.deployments.push(record.clone());
        assert_eq!(upgrade_authorization(Some(&deployed), "upgrade-required"), "unauthorized-immutable-deployment");
        record.type_id = Some(format!("0x{}", "44".repeat(32)));
        record.upgrade_lineage = Some(record.out_point.clone());
        deployed.deployments = vec![record.clone()];
        assert_eq!(upgrade_authorization(Some(&deployed), "upgrade-required"), "invalid-type-id-lineage");
        record.upgrade_lineage = Some(format!("0x{}:1", "55".repeat(32)));
        deployed.deployments = vec![record];
        assert_eq!(upgrade_authorization(Some(&deployed), "upgrade-required"), "external-type-id-proof-required");
    }
}
