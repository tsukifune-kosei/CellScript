use super::{DependencyScope, PackageManager, PackageManifest, PackageSource, ResolutionOptions, ResolvedPackage, WorkspaceConfig};
use crate::edition::CellScriptEdition;
use crate::error::{CompileError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub const WORKSPACE_RESOLVE_GRAPH_SCHEMA: &str = "cellscript-workspace-resolve-graph-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceSelection {
    pub scope: String,
    pub features: Vec<String>,
    pub all_features: bool,
    pub default_features: bool,
    pub environment: Option<String>,
    pub offline: bool,
}

impl From<&ResolutionOptions> for WorkspaceSelection {
    fn from(options: &ResolutionOptions) -> Self {
        Self {
            scope: match options.scope {
                DependencyScope::Runtime => "runtime",
                DependencyScope::Test => "test",
            }
            .to_string(),
            features: options.features.iter().cloned().collect(),
            all_features: options.all_features,
            default_features: !options.no_default_features,
            environment: options.environment.clone(),
            offline: options.offline,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceMemberIdentity {
    pub id: String,
    pub name: String,
    pub namespace: Option<String>,
    pub version: String,
    pub edition: CellScriptEdition,
    pub compiler_requirement: String,
    pub path: String,
    pub manifest_path: String,
    pub manifest_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceMemberEdge {
    pub alias: String,
    pub from_member: String,
    pub to_member: String,
    pub locked_node_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceResolvedNode {
    pub node_id: String,
    pub name: String,
    pub namespace: Option<String>,
    pub version: String,
    pub source_kind: String,
    pub source_identity: String,
    pub source_hash: Option<String>,
    pub manifest_digest: String,
    pub compiler_requirement: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceResolveGraph {
    pub schema: String,
    pub workspace_root: String,
    pub root_is_package: bool,
    pub selection: WorkspaceSelection,
    pub members: BTreeMap<String, WorkspaceMemberIdentity>,
    pub member_edges: Vec<WorkspaceMemberEdge>,
    pub resolved_nodes: BTreeMap<String, WorkspaceResolvedNode>,
    pub build_order: Vec<String>,
}

#[derive(Debug)]
struct LoadedMember {
    identity: WorkspaceMemberIdentity,
    path: PathBuf,
    manifest: PackageManifest,
}

pub fn resolve_workspace_graph(root: &Path, options: &ResolutionOptions) -> Result<WorkspaceResolveGraph> {
    let root = if root.as_os_str().is_empty() { Path::new(".") } else { root };
    let canonical_root = std::fs::canonicalize(root)
        .map_err(|error| CompileError::without_span(format!("failed to canonicalize workspace root '{}': {error}", root.display())))?;
    let (config, root_is_package) = read_workspace_config(&canonical_root)?;
    if !root_is_package && canonical_root.join("Cell.lock").exists() {
        return Err(workspace_error(format!(
            "virtual workspace root '{}' must not contain Cell.lock; member Cell.lock files are independently authoritative",
            canonical_root.display()
        )));
    }
    let loaded = load_members(&canonical_root, &config)?;
    let members = loaded.iter().map(|member| (member.identity.name.clone(), member.identity.clone())).collect::<BTreeMap<_, _>>();
    let member_paths = loaded.iter().map(|member| (member.path.clone(), member.identity.name.clone())).collect::<BTreeMap<_, _>>();
    let mut declared_member_edges = Vec::new();
    for member in &loaded {
        let manager = PackageManager::new(&member.path);
        for (alias, dependency) in manager.selected_dependencies(&member.manifest, options, true)? {
            let super::Dependency::Detailed(detail) = dependency else {
                continue;
            };
            let Some(path) = detail.path else {
                continue;
            };
            let dependency_path = std::fs::canonicalize(member.path.join(path)).map_err(|error| {
                workspace_error(format!(
                    "failed to canonicalize workspace dependency '{}' of member '{}': {error}",
                    alias, member.identity.name
                ))
            })?;
            if let Some(to_member) = member_paths.get(&dependency_path) {
                declared_member_edges.push(WorkspaceMemberEdge {
                    alias,
                    from_member: member.identity.name.clone(),
                    to_member: to_member.clone(),
                    locked_node_id: String::new(),
                });
            }
        }
    }
    declared_member_edges.sort_by(|left, right| {
        (&left.from_member, &left.alias, &left.to_member).cmp(&(&right.from_member, &right.alias, &right.to_member))
    });
    let build_order = topological_member_order(members.keys().cloned().collect(), &declared_member_edges)?;
    let mut member_edges = Vec::new();
    let mut resolved_nodes = BTreeMap::new();
    let mut selected_coordinates: BTreeMap<(Option<String>, String), (String, String)> = BTreeMap::new();

    for member in &loaded {
        let mut manager = PackageManager::new(&member.path);
        manager.resolve_locked_dependencies(options).map_err(|error| {
            workspace_error(format!("workspace member '{}' dependency graph is invalid: {}", member.identity.name, error.message))
                .with_related(vec![error])
        })?;

        for package in manager.get_resolved().values() {
            let coordinate = (package.namespace.clone(), package.name.clone());
            let (source_kind, source_identity, workspace_node_id, instance_identity) =
                workspace_package_identity(&canonical_root, package)?;
            if let Some((selected_identity, selected_node_id)) = selected_coordinates.get(&coordinate) {
                if selected_identity != &instance_identity {
                    return Err(CompileError::without_span(format!(
                        "workspace package instance conflict for '{}': selected '{}' and '{}'",
                        display_coordinate(&coordinate),
                        selected_node_id,
                        workspace_node_id
                    ))
                    .with_code("E2601")
                    .with_details(serde_json::json!({
                        "coordinate": { "namespace": coordinate.0, "name": coordinate.1 },
                        "selected_node_id": selected_node_id,
                        "incoming_node_id": workspace_node_id,
                        "workspace_member": member.identity.name,
                        "phase": "workspace-resolution",
                    })));
                }
            } else {
                selected_coordinates.insert(coordinate, (instance_identity, workspace_node_id.clone()));
            }
            resolved_nodes.entry(workspace_node_id.clone()).or_insert_with(|| WorkspaceResolvedNode {
                node_id: workspace_node_id,
                name: package.name.clone(),
                namespace: package.namespace.clone(),
                version: package.version.clone(),
                source_kind,
                source_identity,
                source_hash: package.source_hash.clone(),
                manifest_digest: package.manifest_digest.clone(),
                compiler_requirement: package.compiler_requirement.clone(),
            });
        }

        for declared in declared_member_edges.iter().filter(|edge| edge.from_member == member.identity.name) {
            let node_id = manager.root_dependencies().get(&declared.alias).ok_or_else(|| {
                workspace_error(format!(
                    "workspace member '{}' edge '{}' is absent from its authoritative Cell.lock selection",
                    member.identity.name, declared.alias
                ))
            })?;
            let package = manager.get_resolved().get(node_id).ok_or_else(|| {
                workspace_error(format!(
                    "workspace member '{}' edge '{}' targets unresolved node '{}'",
                    member.identity.name, declared.alias, node_id
                ))
            })?;
            let canonical_dependency = std::fs::canonicalize(&package.path).map_err(|error| {
                workspace_error(format!(
                    "failed to canonicalize dependency '{}' of workspace member '{}': {error}",
                    declared.alias, member.identity.name
                ))
            })?;
            if member_paths.get(&canonical_dependency) != Some(&declared.to_member) {
                return Err(workspace_error(format!(
                    "workspace member '{}' edge '{}' does not resolve to declared member '{}'",
                    member.identity.name, declared.alias, declared.to_member
                )));
            }
            member_edges.push(WorkspaceMemberEdge { locked_node_id: node_id.clone(), ..declared.clone() });
        }
    }

    member_edges.sort_by(|left, right| {
        (&left.from_member, &left.alias, &left.to_member, &left.locked_node_id).cmp(&(
            &right.from_member,
            &right.alias,
            &right.to_member,
            &right.locked_node_id,
        ))
    });
    Ok(WorkspaceResolveGraph {
        schema: WORKSPACE_RESOLVE_GRAPH_SCHEMA.to_string(),
        workspace_root: canonical_root.to_string_lossy().replace('\\', "/"),
        root_is_package,
        selection: WorkspaceSelection::from(options),
        members,
        member_edges,
        resolved_nodes,
        build_order,
    })
}

pub fn resolve_workspace_member_paths(root: &Path) -> Result<Vec<PathBuf>> {
    let root = if root.as_os_str().is_empty() { Path::new(".") } else { root };
    let canonical_root = std::fs::canonicalize(root)
        .map_err(|error| CompileError::without_span(format!("failed to canonicalize workspace root '{}': {error}", root.display())))?;
    let (config, _) = read_workspace_config(&canonical_root)?;
    Ok(load_members(&canonical_root, &config)?.into_iter().map(|member| member.path).collect())
}

impl WorkspaceResolveGraph {
    pub fn selected_build_order(&self, package: Option<&str>) -> Result<Vec<String>> {
        let Some(package) = package else {
            return Ok(self.build_order.clone());
        };
        if !self.members.contains_key(package) {
            return Err(workspace_error(format!(
                "workspace member '{}' not found; available members: {}",
                package,
                self.members.keys().cloned().collect::<Vec<_>>().join(", ")
            )));
        }
        let mut closure = BTreeSet::new();
        collect_member_closure(package, &self.member_edges, &mut closure);
        Ok(self.build_order.iter().filter(|name| closure.contains(*name)).cloned().collect())
    }
}

fn read_workspace_config(root: &Path) -> Result<(WorkspaceConfig, bool)> {
    let manifest_path = root.join("Cell.toml");
    let source = std::fs::read_to_string(&manifest_path)
        .map_err(|error| workspace_error(format!("failed to read workspace manifest '{}': {error}", manifest_path.display())))?;
    let value: toml::Value = toml::from_str(&source)
        .map_err(|error| workspace_error(format!("failed to parse workspace manifest '{}': {error}", manifest_path.display())))?;
    let root_is_package = value.get("package").is_some();
    let config = if root_is_package {
        let manifest: PackageManifest = toml::from_str(&source).map_err(|error| {
            workspace_error(format!("failed to parse package workspace manifest '{}': {error}", manifest_path.display()))
        })?;
        manifest.workspace.ok_or_else(|| workspace_error("manifest has no [workspace] table"))?
    } else {
        let manifest: super::WorkspaceManifest = toml::from_str(&source).map_err(|error| {
            workspace_error(format!("failed to parse virtual workspace manifest '{}': {error}", manifest_path.display()))
        })?;
        manifest.workspace
    };
    Ok((config, root_is_package))
}

fn load_members(root: &Path, config: &WorkspaceConfig) -> Result<Vec<LoadedMember>> {
    let excluded = canonical_entries(root, &config.exclude, "exclude")?;
    let mut canonical_paths = BTreeSet::new();
    let mut names = BTreeSet::new();
    let mut members = Vec::new();
    for entry in &config.members {
        let candidate = canonical_entry(root, entry, "member")?;
        if excluded.contains(&candidate) {
            continue;
        }
        if !canonical_paths.insert(candidate.clone()) {
            return Err(workspace_error(format!("workspace member path '{}' is listed more than once", candidate.display())));
        }
        let manifest_path = candidate.join("Cell.toml");
        if !manifest_path.is_file() {
            return Err(workspace_error(format!("workspace member '{}' does not contain Cell.toml", entry)));
        }
        let source = std::fs::read(&manifest_path).map_err(|error| {
            workspace_error(format!("failed to read workspace member manifest '{}': {error}", manifest_path.display()))
        })?;
        let manifest = PackageManager::new(&candidate).read_manifest().map_err(|error| {
            workspace_error(format!("workspace member manifest '{}' is invalid: {}", manifest_path.display(), error.message))
                .with_related(vec![error])
        })?;
        if !names.insert(manifest.package.name.clone()) {
            return Err(workspace_error(format!(
                "workspace package name '{}' is declared by more than one member",
                manifest.package.name
            )));
        }
        let relative = candidate.strip_prefix(root).map_err(|_| workspace_error("workspace member escaped the workspace root"))?;
        let relative = relative.to_string_lossy().replace('\\', "/");
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&source)));
        let identity = WorkspaceMemberIdentity {
            id: member_id(&manifest, &relative, &digest),
            name: manifest.package.name.clone(),
            namespace: manifest.package.namespace.clone(),
            version: manifest.package.version.clone(),
            edition: manifest.package.edition,
            compiler_requirement: manifest.package.cellscript_version.clone(),
            path: relative.clone(),
            manifest_path: format!("{relative}/Cell.toml"),
            manifest_digest: digest,
        };
        members.push(LoadedMember { identity, path: candidate, manifest });
    }
    members.sort_by(|left, right| left.identity.name.cmp(&right.identity.name));
    Ok(members)
}

fn canonical_entries(root: &Path, entries: &[String], label: &str) -> Result<BTreeSet<PathBuf>> {
    entries.iter().map(|entry| canonical_entry(root, entry, label)).collect()
}

fn canonical_entry(root: &Path, entry: &str, label: &str) -> Result<PathBuf> {
    let path = std::fs::canonicalize(root.join(entry))
        .map_err(|error| workspace_error(format!("workspace {label} '{}' cannot be resolved: {error}", entry)))?;
    if !path.starts_with(root) {
        return Err(workspace_error(format!("workspace {label} '{}' escapes workspace root '{}'", entry, root.display())));
    }
    if !path.is_dir() {
        return Err(workspace_error(format!("workspace {label} '{}' is not a directory", entry)));
    }
    Ok(path)
}

fn member_id(manifest: &PackageManifest, path: &str, digest: &str) -> String {
    let namespace = manifest.package.namespace.as_deref().unwrap_or("");
    let input = format!("{namespace}\0{}\0{}\0{path}\0{digest}", manifest.package.name, manifest.package.version);
    format!("workspace-member:{}", hex::encode(Sha256::digest(input.as_bytes())))
}

fn workspace_package_identity(root: &Path, package: &ResolvedPackage) -> Result<(String, String, String, String)> {
    let (source_kind, source_identity, node_source) = match &package.source {
        PackageSource::Local(_) => {
            let canonical = std::fs::canonicalize(&package.path).map_err(|error| {
                workspace_error(format!("failed to canonicalize selected package source '{}': {error}", package.path.display()))
            })?;
            let identity = if let Ok(relative) = canonical.strip_prefix(root) {
                format!("workspace:{}", relative.to_string_lossy().replace('\\', "/"))
            } else {
                format!("absolute:{}", canonical.to_string_lossy().replace('\\', "/"))
            };
            ("path".to_string(), identity.clone(), format!("path:{identity}"))
        }
        PackageSource::Git { url, revision } => ("git".to_string(), format!("{url}#{revision}"), format!("git:{url}#{revision}")),
        PackageSource::Registry { registry, url, revision, namespace, version } => (
            "registry".to_string(),
            format!("{registry}:{namespace}@{version}#{revision}:{url}"),
            format!("registry:{registry}:{namespace}/{}@{version}#{revision}", package.name),
        ),
    };
    let selection_suffix = package.node_id.rfind("|compiler=").map(|index| &package.node_id[index..]).ok_or_else(|| {
        workspace_error(format!("selected package node '{}' has no compiler/environment/feature identity", package.node_id))
    })?;
    let coordinate = display_coordinate(&(package.namespace.clone(), package.name.clone()));
    let workspace_node_id = format!("{coordinate}@{}|{node_source}{selection_suffix}", package.version);
    let instance_identity = format!(
        "{workspace_node_id}\0{}\0{}\0{}",
        package.source_hash.as_deref().unwrap_or(""),
        package.manifest_digest,
        package.compiler_requirement
    );
    Ok((source_kind, source_identity, workspace_node_id, instance_identity))
}

fn display_coordinate(coordinate: &(Option<String>, String)) -> String {
    coordinate.0.as_deref().map_or_else(|| coordinate.1.clone(), |namespace| format!("{namespace}/{}", coordinate.1))
}

fn topological_member_order(members: BTreeSet<String>, edges: &[WorkspaceMemberEdge]) -> Result<Vec<String>> {
    let dependencies = members
        .iter()
        .map(|member| {
            let deps =
                edges.iter().filter(|edge| &edge.from_member == member).map(|edge| edge.to_member.clone()).collect::<BTreeSet<_>>();
            (member.clone(), deps)
        })
        .collect::<BTreeMap<_, _>>();
    let mut visiting = Vec::new();
    let mut visited = BTreeSet::new();
    let mut order = Vec::new();
    for member in members {
        visit_member(&member, &dependencies, &mut visiting, &mut visited, &mut order)?;
    }
    Ok(order)
}

fn visit_member(
    member: &str,
    dependencies: &BTreeMap<String, BTreeSet<String>>,
    visiting: &mut Vec<String>,
    visited: &mut BTreeSet<String>,
    order: &mut Vec<String>,
) -> Result<()> {
    if visited.contains(member) {
        return Ok(());
    }
    if let Some(position) = visiting.iter().position(|candidate| candidate == member) {
        let mut cycle = visiting[position..].to_vec();
        cycle.push(member.to_string());
        return Err(workspace_error(format!("workspace member dependency cycle: {}", cycle.join(" -> "))));
    }
    visiting.push(member.to_string());
    if let Some(member_dependencies) = dependencies.get(member) {
        for dependency in member_dependencies {
            visit_member(dependency, dependencies, visiting, visited, order)?;
        }
    }
    visiting.pop();
    visited.insert(member.to_string());
    order.push(member.to_string());
    Ok(())
}

fn collect_member_closure(member: &str, edges: &[WorkspaceMemberEdge], closure: &mut BTreeSet<String>) {
    if !closure.insert(member.to_string()) {
        return;
    }
    for dependency in edges.iter().filter(|edge| edge.from_member == member) {
        collect_member_closure(&dependency.to_member, edges, closure);
    }
}

fn workspace_error(message: impl Into<String>) -> CompileError {
    CompileError::without_span(message).with_code("E2700")
}
