//! Stable, read-only package resolution and build-unit inspection schemas.

use super::workspace::{canonical_package_identity, resolve_workspace_graph};
use super::{DependencyScope, Lockfile, PackageManager, PackageManifest, ResolutionOptions};
use crate::edition::{resolve_compatibility_profile, CellScriptEdition, ResolvedCompatibilityProfile};
use crate::error::{CompileError, Result};
use crate::{ArtifactFormat, CompileOptions, TargetProfile};
use camino::Utf8PathBuf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub const RESOLVE_GRAPH_SCHEMA: &str = "cellscript-resolve-graph-v1";
pub const BUILD_PLAN_SCHEMA: &str = "cellscript-build-plan-v1";
pub const INSPECTION_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SelectionProvenance {
    pub scope: String,
    pub scope_source: String,
    pub requested_features: Vec<String>,
    pub effective_features: Vec<String>,
    pub feature_source: String,
    pub all_features: bool,
    pub default_features: bool,
    pub environment: Option<String>,
    pub environment_source: String,
    pub requested_offline: bool,
    pub effective_offline: bool,
    pub lock_mode: String,
    pub mutable_resolution_allowed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResolveRoot {
    pub id: String,
    pub member_name: String,
    pub package_name: String,
    pub namespace: Option<String>,
    pub version: String,
    pub edition: CellScriptEdition,
    pub compiler_requirement: String,
    pub path: String,
    pub manifest_path: String,
    pub manifest_digest: String,
    pub lock_status: String,
    pub lockfile_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResolvePackageNode {
    pub id: String,
    pub lock_node_ids: BTreeMap<String, String>,
    pub name: String,
    pub namespace: Option<String>,
    pub version: String,
    pub edition: CellScriptEdition,
    pub compiler_requirement: String,
    pub source_kind: String,
    pub source_identity: String,
    pub source_hash: Option<String>,
    pub manifest_digest: String,
    pub effective_features: Vec<String>,
    pub environment_identity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResolveEdge {
    pub from: String,
    pub alias: String,
    pub to: String,
    pub dependency_kind: String,
    pub provenance: String,
    pub root: String,
    pub locked_node_id: String,
    pub workspace_member_target: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StaleLockNode {
    pub root: String,
    pub locked_node_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InspectionWarning {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolveLockSnapshot {
    pub root: String,
    pub path: String,
    pub content_sha256: String,
    pub content: String,
    pub document: Lockfile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolveGraph {
    pub schema: String,
    pub schema_version: u32,
    pub compiler_version: String,
    pub graph_digest: String,
    pub resolution_digest: String,
    pub root_kind: String,
    pub workspace_root: String,
    pub selection: SelectionProvenance,
    pub roots: Vec<ResolveRoot>,
    pub nodes: BTreeMap<String, ResolvePackageNode>,
    pub edges: Vec<ResolveEdge>,
    pub build_order: Vec<String>,
    pub stale_nodes: Vec<StaleLockNode>,
    pub warnings: Vec<InspectionWarning>,
    pub lockfiles: Vec<ResolveLockSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BuildPlanSelection {
    pub target: String,
    pub artifact_format: String,
    pub target_profile: String,
    pub optimization_level: u8,
    pub debug: bool,
    pub release: bool,
    pub primitive_compat: Option<String>,
    pub entry_action: Option<String>,
    pub entry_lock: Option<String>,
    pub artifact: Option<String>,
    pub production: bool,
    pub deny_fail_closed: bool,
    pub deny_ckb_runtime: bool,
    pub deny_runtime_obligations: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BuildUnitOutputs {
    pub artifact: String,
    pub metadata: String,
    pub lowering_record: Option<String>,
    pub source_map: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BuildUnitCache {
    pub cacheable: bool,
    pub cache_key: String,
    pub source_set_hash: String,
    pub status: String,
    pub rebuild_reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BuildUnit {
    pub id: String,
    pub package_root: String,
    pub package_name: String,
    pub package_version: String,
    pub source_identity: String,
    pub entry: String,
    pub target: String,
    pub artifact_format: String,
    pub target_profile: String,
    pub vm_abi: String,
    pub codec_identity: String,
    pub compatibility_profile: ResolvedCompatibilityProfile,
    pub dependency_scope: String,
    pub features: Vec<String>,
    pub environment: Option<String>,
    pub direct_dependencies: Vec<String>,
    pub outputs: BuildUnitOutputs,
    pub cache: BuildUnitCache,
    pub production_requirements: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildPlan {
    pub schema: String,
    pub schema_version: u32,
    pub compiler_version: String,
    pub plan_digest: String,
    pub resolve_graph_schema: String,
    pub resolve_graph_digest: String,
    pub resolve_resolution_digest: String,
    pub selection: BuildPlanSelection,
    pub units: Vec<BuildUnit>,
    pub unit_order: Vec<String>,
    pub warnings: Vec<InspectionWarning>,
}

#[derive(Debug, Clone, Default)]
pub struct BuildPlanOptions {
    pub target: Option<String>,
    pub target_profile: Option<String>,
    pub release: bool,
    pub debug: bool,
    pub primitive_compat: Option<String>,
    pub entry_action: Option<String>,
    pub entry_lock: Option<String>,
    pub artifact: Option<String>,
    pub production: bool,
    pub deny_fail_closed: bool,
    pub deny_ckb_runtime: bool,
    pub deny_runtime_obligations: bool,
}

pub fn validate_schema_version(version: u32) -> Result<()> {
    if version != INSPECTION_SCHEMA_VERSION {
        return Err(CompileError::without_span(format!(
            "unsupported inspection schema version {version}; expected {INSPECTION_SCHEMA_VERSION}"
        )));
    }
    Ok(())
}

pub fn resolve_graph(input: &Path, selected_package: Option<&str>, requested_options: &ResolutionOptions) -> Result<ResolveGraph> {
    let root = find_manifest_root(input)?;
    let source = std::fs::read_to_string(root.join("Cell.toml"))?;
    let value: toml::Value = toml::from_str(&source)?;
    let is_workspace = value.get("workspace").is_some();
    let mut effective_options = requested_options.clone();
    effective_options.offline = true;
    let selection = selection_provenance(requested_options, &effective_options);

    let (root_kind, selected_roots, build_order, workspace_member_paths) = if is_workspace {
        let workspace = resolve_workspace_graph(&root, &effective_options)?;
        let order = workspace.selected_build_order(selected_package)?;
        let paths = workspace
            .members
            .values()
            .map(|member| (std::fs::canonicalize(root.join(&member.path)), member.name.clone()))
            .map(|(path, name)| path.map(|path| (path, name)))
            .collect::<std::io::Result<BTreeMap<_, _>>>()?;
        let roots = order
            .iter()
            .map(|name| {
                let member = &workspace.members[name];
                (member.id.clone(), name.clone(), root.join(&member.path))
            })
            .collect::<Vec<_>>();
        ("workspace".to_string(), roots, order, paths)
    } else {
        if selected_package.is_some() {
            return Err(CompileError::without_span("--package requires a [workspace] manifest"));
        }
        let manifest = PackageManager::new(&root).read_manifest()?;
        let bytes = std::fs::read(root.join("Cell.toml"))?;
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
        let root_id = package_root_id(&manifest, &digest);
        (
            "package".to_string(),
            vec![(root_id.clone(), manifest.package.name.clone(), root.clone())],
            vec![manifest.package.name],
            BTreeMap::new(),
        )
    };

    let mut roots = Vec::new();
    let mut nodes: BTreeMap<String, ResolvePackageNode> = BTreeMap::new();
    let mut edges = Vec::new();
    let mut stale_nodes = Vec::new();
    let mut warnings = Vec::new();
    let mut lockfiles = Vec::new();

    for (root_id, member_name, package_root) in &selected_roots {
        let manager = &mut PackageManager::new(package_root);
        let manifest = manager.read_manifest()?;
        manager.resolve_locked_dependencies(&effective_options)?;
        let manifest_bytes = std::fs::read(package_root.join("Cell.toml"))?;
        let manifest_digest = format!("sha256:{}", hex::encode(Sha256::digest(&manifest_bytes)));
        let lock_snapshot = read_lock_snapshot(&root, root_id, package_root)?;
        let lock_status = if lock_snapshot.is_some() { "authoritative-current" } else { "absent-no-selected-dependencies" };
        let lockfile_sha256 = lock_snapshot.as_ref().map(|snapshot| snapshot.content_sha256.clone());
        let root_path = normalized_path(&root, package_root)?;
        roots.push(ResolveRoot {
            id: root_id.clone(),
            member_name: member_name.clone(),
            package_name: manifest.package.name.clone(),
            namespace: manifest.package.namespace.clone(),
            version: manifest.package.version.clone(),
            edition: manifest.package.edition,
            compiler_requirement: manifest.package.cellscript_version.clone(),
            path: root_path.clone(),
            manifest_path: if root_path == "." { "Cell.toml".to_string() } else { format!("{root_path}/Cell.toml") },
            manifest_digest,
            lock_status: lock_status.to_string(),
            lockfile_sha256,
        });

        let mut lock_to_canonical = BTreeMap::new();
        for (locked_node_id, package) in manager.get_resolved() {
            let identity = canonical_package_identity(&root, package)?;
            let opaque_node_id = opaque_package_node_id(&identity.instance_identity);
            let dependency_manifest = PackageManager::new(&package.path).read_manifest()?;
            let (features, environment) = node_selection(&identity.node_id)?;
            lock_to_canonical.insert(locked_node_id.clone(), opaque_node_id.clone());
            let node = nodes.entry(opaque_node_id.clone()).or_insert_with(|| ResolvePackageNode {
                id: opaque_node_id,
                lock_node_ids: BTreeMap::new(),
                name: package.name.clone(),
                namespace: package.namespace.clone(),
                version: package.version.clone(),
                edition: dependency_manifest.package.edition,
                compiler_requirement: package.compiler_requirement.clone(),
                source_kind: identity.source_kind,
                source_identity: identity.source_identity,
                source_hash: package.source_hash.clone(),
                manifest_digest: package.manifest_digest.clone(),
                effective_features: features,
                environment_identity: environment,
            });
            node.lock_node_ids.insert(root_id.clone(), locked_node_id.clone());
        }

        for (alias, locked_node_id) in manager.root_dependencies() {
            let to = lock_to_canonical.get(locked_node_id).ok_or_else(|| {
                CompileError::without_span(format!("root edge '{alias}' targets unselected lock node '{locked_node_id}'"))
            })?;
            let kind = if effective_options.scope == DependencyScope::Test
                && manifest.dev_dependencies.contains_key(alias)
                && !manifest.dependencies.contains_key(alias)
            {
                "test"
            } else {
                "runtime"
            };
            let workspace_member_target = manager
                .get_resolved()
                .get(locked_node_id)
                .and_then(|package| std::fs::canonicalize(&package.path).ok())
                .and_then(|path| workspace_member_paths.get(&path).cloned());
            edges.push(ResolveEdge {
                from: root_id.clone(),
                alias: alias.clone(),
                to: to.clone(),
                dependency_kind: kind.to_string(),
                provenance: root_edge_provenance(&effective_options).to_string(),
                root: root_id.clone(),
                locked_node_id: locked_node_id.clone(),
                workspace_member_target,
            });
        }
        for (locked_node_id, package) in manager.get_resolved() {
            let from = lock_to_canonical[locked_node_id].clone();
            for (alias, target_locked_node_id) in &package.dependencies {
                let to = lock_to_canonical.get(target_locked_node_id).ok_or_else(|| {
                    CompileError::without_span(format!(
                        "lock node '{locked_node_id}' edge '{alias}' targets unselected node '{target_locked_node_id}'"
                    ))
                })?;
                edges.push(ResolveEdge {
                    from: from.clone(),
                    alias: alias.clone(),
                    to: to.clone(),
                    dependency_kind: "runtime".to_string(),
                    provenance: "locked-transitive-edge".to_string(),
                    root: root_id.clone(),
                    locked_node_id: target_locked_node_id.clone(),
                    workspace_member_target: None,
                });
            }
        }

        if let Some(snapshot) = lock_snapshot {
            let selected = manager.get_resolved().keys().cloned().collect::<BTreeSet<_>>();
            for locked_node_id in snapshot.document.dependencies.keys().filter(|node| !selected.contains(*node)) {
                stale_nodes.push(StaleLockNode {
                    root: root_id.clone(),
                    locked_node_id: locked_node_id.clone(),
                    reason: "not-selected-by-current-scope-features-environment".to_string(),
                });
            }
            lockfiles.push(snapshot);
        }
    }

    edges.sort_by(|left, right| {
        (&left.from, &left.alias, &left.to, &left.root, &left.locked_node_id).cmp(&(
            &right.from,
            &right.alias,
            &right.to,
            &right.root,
            &right.locked_node_id,
        ))
    });
    stale_nodes.sort_by(|left, right| (&left.root, &left.locked_node_id).cmp(&(&right.root, &right.locked_node_id)));
    if !stale_nodes.is_empty() {
        warnings.push(InspectionWarning {
            code: "unselected-lock-nodes".to_string(),
            message: format!("{} lock node(s) are not selected by this query", stale_nodes.len()),
        });
    }
    if !requested_options.offline {
        warnings.push(InspectionWarning {
            code: "read-only-lock-selection".to_string(),
            message:
                "inspection forced offline and consumed existing Cell.lock state; run `cellc update` explicitly for mutable resolution"
                    .to_string(),
        });
    }
    let build_order = build_order
        .iter()
        .map(|name| {
            selected_roots
                .iter()
                .find(|(_, member_name, _)| member_name == name)
                .map(|(id, _, _)| id.clone())
                .ok_or_else(|| CompileError::without_span(format!("selected root '{name}' is absent from inspection graph")))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut graph = ResolveGraph {
        schema: RESOLVE_GRAPH_SCHEMA.to_string(),
        schema_version: INSPECTION_SCHEMA_VERSION,
        compiler_version: crate::VERSION.to_string(),
        graph_digest: String::new(),
        resolution_digest: String::new(),
        root_kind,
        workspace_root: root.to_string_lossy().replace('\\', "/"),
        selection,
        roots,
        nodes,
        edges,
        build_order,
        stale_nodes,
        warnings,
        lockfiles,
    };
    graph.resolution_digest = resolution_digest(&graph)?;
    graph.graph_digest = schema_digest(&graph)?;
    Ok(graph)
}

pub fn build_plan(graph: &ResolveGraph, options: &BuildPlanOptions) -> Result<BuildPlan> {
    validate_entry_selection(options)?;
    let root_path = Path::new(&graph.workspace_root);
    let mut units = Vec::new();
    let mut root_to_unit = BTreeMap::new();

    for root_id in &graph.build_order {
        let root = graph
            .roots
            .iter()
            .find(|root| &root.id == root_id)
            .ok_or_else(|| CompileError::without_span(format!("build root '{root_id}' is absent from resolve graph")))?;
        let package_root = if root.path == "." { root_path.to_path_buf() } else { root_path.join(&root.path) };
        let manifest = PackageManager::new(&package_root).read_manifest()?;
        let target = options.target.clone().or_else(|| manifest.build.target.clone()).unwrap_or_else(|| "riscv64-asm".to_string());
        let artifact_format = ArtifactFormat::from_target(&target)?;
        let target_profile = options
            .target_profile
            .clone()
            .or_else(|| manifest.build.target_profile.clone())
            .unwrap_or_else(|| TargetProfile::Ckb.name().to_string());
        let target_profile_kind = TargetProfile::from_name(&target_profile)?;
        let entry = selected_entry(&manifest, options)?;
        let mut compatibility_profile =
            resolve_compatibility_profile(manifest.package.edition, &target_profile, options.primitive_compat.as_deref());
        if options.artifact.is_some() {
            crate::edition::set_entry_compatibility_profile(
                &mut compatibility_profile,
                crate::policy_witness::POLICY_WITNESS_ABI,
                crate::artifact::POLICY_WITNESS_PLACEMENT_ABI,
                crate::artifact::POLICY_WITNESS_PLACEMENT_FIELD,
                crate::artifact::POLICY_WITNESS_PLACEMENT_SOURCE,
            );
        }
        let cache_options = CompileOptions {
            edition: manifest.package.edition,
            opt_level: if options.release { 3 } else { 1 },
            output: None,
            debug: options.debug,
            target: options.target.clone(),
            target_profile: options.target_profile.clone(),
            primitive_compat: options.primitive_compat.clone(),
        };
        let identity_options =
            CompileOptions { target: Some(target.clone()), target_profile: Some(target_profile.clone()), ..cache_options.clone() };
        let package_utf8 = Utf8PathBuf::from_path_buf(package_root.clone())
            .map_err(|path| CompileError::without_span(format!("package path '{}' is not valid UTF-8", path.display())))?;
        let resolved_input = crate::resolve_input_path(&package_utf8)?;
        let output = crate::default_output_path_for_input(&package_utf8, &resolved_input, artifact_format)?;
        let metadata = crate::default_metadata_path_for_artifact(&output);
        let (lowering_record, source_map) = if artifact_format == ArtifactFormat::RiscvElf {
            (
                Some(crate::lowering_record_output_path_from_artifact(&output).to_string()),
                Some(crate::source_map_output_path_from_artifact(&output).to_string()),
            )
        } else {
            (None, None)
        };
        let cache_probe = crate::inspect_incremental_cache(&package_utf8, &cache_options)?;
        let cacheable = options.entry_action.is_none() && options.entry_lock.is_none() && options.artifact.is_none();
        let cache = if cacheable {
            BuildUnitCache {
                cacheable,
                cache_key: cache_probe.cache_key,
                source_set_hash: cache_probe.source_set_hash,
                status: cache_probe.status,
                rebuild_reason: cache_probe.rebuild_reason,
            }
        } else {
            BuildUnitCache {
                cacheable,
                cache_key: cache_probe.cache_key,
                source_set_hash: cache_probe.source_set_hash,
                status: "not-cacheable".to_string(),
                rebuild_reason: "entry-scoped-build".to_string(),
            }
        };
        let source_identity = format!("{}@{}#{}", root.package_name, root.version, root.manifest_digest);
        let production_requirements = production_requirements(&manifest, options);
        let vm_abi = target_profile_kind.metadata(artifact_format).vm_abi;
        let outputs = BuildUnitOutputs { artifact: output.to_string(), metadata: metadata.to_string(), lowering_record, source_map };
        let unit_id = build_unit_id(
            &graph.resolution_digest,
            root_id,
            &entry,
            &identity_options,
            &graph.selection,
            &outputs,
            &production_requirements,
        )?;
        root_to_unit.insert(root_id.clone(), unit_id.clone());
        units.push(BuildUnit {
            id: unit_id,
            package_root: root_id.clone(),
            package_name: root.package_name.clone(),
            package_version: root.version.clone(),
            source_identity,
            entry,
            target,
            artifact_format: artifact_format.display_name().to_string(),
            target_profile,
            vm_abi,
            codec_identity: compatibility_profile.entry_witness_payload_abi.clone(),
            compatibility_profile,
            dependency_scope: graph.selection.scope.clone(),
            features: graph.selection.effective_features.clone(),
            environment: graph.selection.environment.clone(),
            direct_dependencies: Vec::new(),
            outputs,
            cache,
            production_requirements,
        });
    }

    for unit in &mut units {
        let dependencies = graph
            .edges
            .iter()
            .filter(|edge| edge.from == unit.package_root)
            .filter_map(|edge| edge.workspace_member_target.as_deref())
            .filter_map(|member_name| graph.roots.iter().find(|root| root.member_name == member_name))
            .filter_map(|root| root_to_unit.get(&root.id))
            .cloned()
            .collect::<BTreeSet<_>>();
        unit.direct_dependencies = dependencies.into_iter().collect();
    }
    let unit_order = units.iter().map(|unit| unit.id.clone()).collect();
    if units.is_empty() {
        return Err(CompileError::without_span("build plan has no selected package units"));
    }
    let target = common_unit_value(&units, |unit| &unit.target);
    let artifact_format = common_unit_value(&units, |unit| &unit.artifact_format);
    let target_profile = common_unit_value(&units, |unit| &unit.target_profile);
    let selection = BuildPlanSelection {
        target,
        artifact_format,
        target_profile,
        optimization_level: if options.release { 3 } else { 1 },
        debug: options.debug,
        release: options.release,
        primitive_compat: options.primitive_compat.clone(),
        entry_action: options.entry_action.clone(),
        entry_lock: options.entry_lock.clone(),
        artifact: options.artifact.clone(),
        production: options.production,
        deny_fail_closed: options.deny_fail_closed,
        deny_ckb_runtime: options.deny_ckb_runtime,
        deny_runtime_obligations: options.deny_runtime_obligations,
    };
    let mut plan = BuildPlan {
        schema: BUILD_PLAN_SCHEMA.to_string(),
        schema_version: INSPECTION_SCHEMA_VERSION,
        compiler_version: crate::VERSION.to_string(),
        plan_digest: String::new(),
        resolve_graph_schema: graph.schema.clone(),
        resolve_graph_digest: graph.graph_digest.clone(),
        resolve_resolution_digest: graph.resolution_digest.clone(),
        selection,
        units,
        unit_order,
        warnings: graph.warnings.clone(),
    };
    plan.plan_digest = schema_digest(&plan)?;
    Ok(plan)
}

fn selection_provenance(requested: &ResolutionOptions, effective: &ResolutionOptions) -> SelectionProvenance {
    let requested_features = requested.features.iter().cloned().collect::<Vec<_>>();
    let mut effective_features = effective.features.iter().cloned().collect::<Vec<_>>();
    if effective.all_features {
        effective_features.push("*".to_string());
    }
    if !effective.no_default_features {
        effective_features.push("default".to_string());
    }
    effective_features.sort();
    SelectionProvenance {
        scope: match effective.scope {
            DependencyScope::Runtime => "runtime",
            DependencyScope::Test => "test",
        }
        .to_string(),
        scope_source: if effective.scope == DependencyScope::Runtime { "default" } else { "cli" }.to_string(),
        requested_features,
        effective_features,
        feature_source: if requested.features.is_empty() && !requested.all_features && !requested.no_default_features {
            "default"
        } else {
            "cli"
        }
        .to_string(),
        all_features: effective.all_features,
        default_features: !effective.no_default_features,
        environment: effective.environment.clone(),
        environment_source: if effective.environment.is_some() { "cli" } else { "default" }.to_string(),
        requested_offline: requested.offline,
        effective_offline: true,
        lock_mode: "read-only-authoritative".to_string(),
        mutable_resolution_allowed: false,
    }
}

fn find_manifest_root(input: &Path) -> Result<PathBuf> {
    let input = if input.as_os_str().is_empty() { Path::new(".") } else { input };
    let input = std::fs::canonicalize(input).map_err(|error| {
        CompileError::without_span(format!("failed to canonicalize inspection input '{}': {error}", input.display()))
    })?;
    let mut cursor = if input.is_dir() { input } else { input.parent().unwrap_or(&input).to_path_buf() };
    loop {
        if cursor.join("Cell.toml").is_file() {
            return Ok(cursor);
        }
        if !cursor.pop() {
            return Err(CompileError::without_span("inspection input is not inside a CellScript package or workspace"));
        }
    }
}

fn read_lock_snapshot(workspace_root: &Path, root_id: &str, package_root: &Path) -> Result<Option<ResolveLockSnapshot>> {
    let path = package_root.join("Cell.lock");
    if !path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(&path)?;
    let document = Lockfile::read_from_root(package_root)?.ok_or_else(|| CompileError::without_span("Cell.lock disappeared"))?;
    Ok(Some(ResolveLockSnapshot {
        root: root_id.to_string(),
        path: normalized_path(workspace_root, &path)?,
        content_sha256: hex::encode(Sha256::digest(content.as_bytes())),
        content,
        document,
    }))
}

fn normalized_path(root: &Path, path: &Path) -> Result<String> {
    let canonical_root = std::fs::canonicalize(root)?;
    let canonical = std::fs::canonicalize(path)?;
    let relative = canonical.strip_prefix(&canonical_root).map_err(|_| {
        CompileError::without_span(format!("inspection path '{}' escapes root '{}'", canonical.display(), canonical_root.display()))
    })?;
    let value = relative.to_string_lossy().replace('\\', "/");
    Ok(if value.is_empty() { ".".to_string() } else { value })
}

fn package_root_id(manifest: &PackageManifest, manifest_digest: &str) -> String {
    let identity = format!(
        "{}\0{}\0{}\0{}",
        manifest.package.namespace.as_deref().unwrap_or(""),
        manifest.package.name,
        manifest.package.version,
        manifest_digest
    );
    format!("package-root:{}", hex::encode(Sha256::digest(identity.as_bytes())))
}

fn opaque_package_node_id(instance_identity: &str) -> String {
    format!("package-node:{}", hex::encode(Sha256::digest(instance_identity.as_bytes())))
}

fn node_selection(node_id: &str) -> Result<(Vec<String>, String)> {
    let environment = node_id
        .split_once("|env=")
        .and_then(|(_, suffix)| suffix.split_once("|features="))
        .map(|(environment, _)| environment.to_string())
        .ok_or_else(|| CompileError::without_span(format!("canonical package node '{node_id}' has no environment identity")))?;
    let features = node_id
        .rsplit_once("|features=")
        .map(|(_, features)| features.split(',').filter(|feature| !feature.is_empty()).map(str::to_string).collect::<Vec<_>>())
        .ok_or_else(|| CompileError::without_span(format!("canonical package node '{node_id}' has no feature identity")))?;
    Ok((features, environment))
}

fn root_edge_provenance(options: &ResolutionOptions) -> &'static str {
    if options.environment.is_some() {
        "locked-environment-root-edge"
    } else if options.scope == DependencyScope::Test {
        "locked-test-root-edge"
    } else {
        "locked-runtime-root-edge"
    }
}

fn selected_entry(manifest: &PackageManifest, options: &BuildPlanOptions) -> Result<String> {
    if let Some(artifact) = options.artifact.as_deref() {
        crate::artifact::validate_declarations(&manifest.artifacts)?;
        if !manifest.artifacts.iter().any(|declaration| declaration.name == artifact) {
            return Err(CompileError::without_span(format!("artifact '{artifact}' is not declared in Cell.toml")));
        }
        return Ok(format!("artifact:{artifact}"));
    }
    if let Some(action) = options.entry_action.as_deref() {
        return Ok(format!("action:{action}"));
    }
    if let Some(lock) = options.entry_lock.as_deref() {
        return Ok(format!("lock:{lock}"));
    }
    Ok(format!("package:{}", manifest.package.entry))
}

fn validate_entry_selection(options: &BuildPlanOptions) -> Result<()> {
    if [options.artifact.is_some(), options.entry_action.is_some(), options.entry_lock.is_some()]
        .into_iter()
        .filter(|selected| *selected)
        .count()
        > 1
    {
        return Err(CompileError::without_span("--artifact, --entry-action, and --entry-lock are mutually exclusive"));
    }
    Ok(())
}

fn production_requirements(manifest: &PackageManifest, options: &BuildPlanOptions) -> Vec<String> {
    let mut requirements = Vec::new();
    if manifest.policy.production || options.production {
        requirements.push("production".to_string());
    }
    if manifest.policy.deny_fail_closed || options.deny_fail_closed {
        requirements.push("deny-fail-closed".to_string());
    }
    if manifest.policy.deny_ckb_runtime || options.deny_ckb_runtime {
        requirements.push("deny-ckb-runtime".to_string());
    }
    if manifest.policy.deny_runtime_obligations || options.deny_runtime_obligations {
        requirements.push("deny-runtime-obligations".to_string());
    }
    requirements
}

fn build_unit_id(
    graph_digest: &str,
    root_id: &str,
    entry: &str,
    compile_options: &CompileOptions,
    dependency_selection: &SelectionProvenance,
    outputs: &BuildUnitOutputs,
    production_requirements: &[String],
) -> Result<String> {
    let value = serde_json::json!({
        "schema": BUILD_PLAN_SCHEMA,
        "graph_digest": graph_digest,
        "root": root_id,
        "entry": entry,
        "compile": {
            "edition": compile_options.edition,
            "optimization_level": compile_options.opt_level,
            "debug": compile_options.debug,
            "target": compile_options.target,
            "target_profile": compile_options.target_profile,
            "primitive_compat": compile_options.primitive_compat,
        },
        "dependency_selection": dependency_selection,
        "outputs": outputs,
        "production_requirements": production_requirements,
    });
    let bytes = serde_json::to_vec(&value)?;
    Ok(format!("build-unit:{}", hex::encode(Sha256::digest(bytes))))
}

fn schema_digest<T: Serialize>(value: &T) -> Result<String> {
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(serde_json::to_vec(value)?))))
}

fn common_unit_value(units: &[BuildUnit], select: impl Fn(&BuildUnit) -> &String) -> String {
    let values = units.iter().map(select).collect::<BTreeSet<_>>();
    if values.len() == 1 {
        (*values.into_iter().next().expect("one value")).clone()
    } else {
        "per-unit".to_string()
    }
}

fn resolution_digest(graph: &ResolveGraph) -> Result<String> {
    schema_digest(&serde_json::json!({
        "schema": RESOLVE_GRAPH_SCHEMA,
        "schema_version": INSPECTION_SCHEMA_VERSION,
        "compiler_version": graph.compiler_version,
        "root_kind": graph.root_kind,
        "selection": {
            "scope": graph.selection.scope,
            "effective_features": graph.selection.effective_features,
            "all_features": graph.selection.all_features,
            "default_features": graph.selection.default_features,
            "environment": graph.selection.environment,
            "lock_mode": graph.selection.lock_mode,
        },
        "roots": graph.roots.iter().map(|root| serde_json::json!({
            "id": root.id,
            "package_name": root.package_name,
            "namespace": root.namespace,
            "version": root.version,
            "edition": root.edition,
            "compiler_requirement": root.compiler_requirement,
            "path": root.path,
            "manifest_digest": root.manifest_digest,
        })).collect::<Vec<_>>(),
        "nodes": graph.nodes,
        "edges": graph.edges,
        "build_order": graph.build_order,
    }))
}
