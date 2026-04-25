use crate::error::{CompileError, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageManifest {
    pub package: PackageInfo,
    #[serde(default)]
    pub dependencies: HashMap<String, Dependency>,
    #[serde(default)]
    pub dev_dependencies: HashMap<String, Dependency>,
    #[serde(default)]
    pub build: BuildConfig,
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default)]
    pub deploy: DeployConfig,
    #[serde(default)]
    pub metadata: HashMap<String, toml::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageInfo {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub authors: Vec<String>,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub license: String,
    #[serde(default)]
    pub repository: String,
    #[serde(default)]
    pub homepage: String,
    #[serde(default)]
    pub documentation: String,
    #[serde(default)]
    pub keywords: Vec<String>,
    #[serde(default)]
    pub categories: Vec<String>,
    #[serde(default)]
    pub cellscript_version: String,
    #[serde(default = "default_entry")]
    pub entry: String,
    #[serde(default)]
    pub source_roots: Vec<String>,
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
}

fn default_entry() -> String {
    "src/main.cell".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Dependency {
    Simple(String),
    Detailed(DetailedDependency),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetailedDependency {
    #[serde(default = "default_any_version")]
    pub version: String,
    #[serde(default)]
    pub git: Option<String>,
    #[serde(default)]
    pub branch: Option<String>,
    #[serde(default)]
    pub tag: Option<String>,
    #[serde(default)]
    pub rev: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub optional: bool,
    #[serde(default)]
    pub features: Vec<String>,
    #[serde(default = "default_true")]
    pub default_features: bool,
}

fn default_true() -> bool {
    true
}

fn default_any_version() -> String {
    "*".to_string()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BuildConfig {
    #[serde(default)]
    pub script: Option<String>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub target_profile: Option<String>,
    #[serde(default)]
    pub out_dir: Option<String>,
    #[serde(default)]
    pub dependencies: HashMap<String, Dependency>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyConfig {
    #[serde(default)]
    pub production: bool,
    #[serde(default)]
    pub deny_fail_closed: bool,
    #[serde(default)]
    pub deny_symbolic_runtime: bool,
    #[serde(default)]
    pub deny_ckb_runtime: bool,
    #[serde(default)]
    pub deny_runtime_obligations: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeployConfig {
    #[serde(default)]
    pub spora: Option<SporaDeployConfig>,
    #[serde(default)]
    pub ckb: Option<CkbDeployConfig>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SporaDeployConfig {
    #[serde(default)]
    pub artifact_hash: Option<String>,
    #[serde(default)]
    pub schema_hash: Option<String>,
    #[serde(default)]
    pub abi_hash: Option<String>,
    #[serde(default)]
    pub code_cell: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CkbDeployConfig {
    #[serde(default)]
    pub artifact_hash: Option<String>,
    #[serde(default)]
    pub data_hash: Option<String>,
    #[serde(default)]
    pub out_point: Option<String>,
    #[serde(default)]
    pub dep_type: Option<String>,
    #[serde(default)]
    pub hash_type: Option<String>,
    #[serde(default)]
    pub type_id: Option<String>,
    #[serde(default)]
    pub cell_deps: Vec<CkbCellDepConfig>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CkbCellDepConfig {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub out_point: Option<String>,
    #[serde(default)]
    pub tx_hash: Option<String>,
    #[serde(default)]
    pub index: Option<u32>,
    #[serde(default)]
    pub dep_type: Option<String>,
    #[serde(default)]
    pub data_hash: Option<String>,
    #[serde(default)]
    pub hash_type: Option<String>,
    #[serde(default)]
    pub type_id: Option<String>,
}

pub struct PackageManager {
    root: PathBuf,
    resolved: HashMap<String, ResolvedPackage>,
}

#[derive(Debug, Clone)]
pub struct ResolvedPackage {
    pub name: String,
    pub version: String,
    pub path: PathBuf,
    pub source: PackageSource,
    pub dependencies: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum PackageSource {
    Local(PathBuf),
    Git { url: String, revision: String },
    Registry { name: String, version: String },
}

#[derive(Debug, Clone)]
pub enum VersionReq {
    Exact(String),
    Compatible(String),
    Range(String),
    Any,
}

impl PackageManager {
    pub fn new(root: impl AsRef<Path>) -> Self {
        let root = root.as_ref().to_path_buf();

        Self { root, resolved: HashMap::new() }
    }

    pub fn read_manifest(&self) -> Result<PackageManifest> {
        let manifest_path = self.root.join("Cell.toml");

        if !manifest_path.exists() {
            return Err(CompileError::without_span("Cell.toml not found. Run 'cellc init' to create a new package."));
        }

        let content = std::fs::read_to_string(&manifest_path)?;
        let manifest: PackageManifest = toml::from_str(&content)?;

        Ok(manifest)
    }

    pub fn write_manifest(&self, manifest: &PackageManifest) -> Result<()> {
        let manifest_path = self.root.join("Cell.toml");
        let content = toml::to_string_pretty(manifest)?;
        std::fs::write(&manifest_path, content)?;
        Ok(())
    }

    pub fn init(&self, name: &str) -> Result<()> {
        self.init_with_entry(
            name,
            "src/main.cell",
            format!(
                r#"module {};

// Entry point for {}
"#,
                name, name
            ),
        )
    }

    pub fn init_library(&self, name: &str) -> Result<()> {
        self.init_with_entry(name, "src/lib.cell", format!("module {};\n", name))
    }

    fn init_with_entry(&self, name: &str, entry: &str, entry_content: String) -> Result<()> {
        std::fs::create_dir_all(self.root.join("src"))?;
        std::fs::create_dir_all(self.root.join("tests"))?;
        std::fs::create_dir_all(self.root.join("examples"))?;

        let manifest = PackageManifest {
            package: PackageInfo {
                name: name.to_string(),
                version: "0.1.0".to_string(),
                authors: vec![],
                description: String::new(),
                license: String::new(),
                repository: String::new(),
                homepage: String::new(),
                documentation: String::new(),
                keywords: vec![],
                categories: vec![],
                cellscript_version: String::new(),
                entry: entry.to_string(),
                source_roots: vec![],
                include: vec![],
                exclude: vec![],
            },
            dependencies: HashMap::new(),
            dev_dependencies: HashMap::new(),
            build: BuildConfig::default(),
            policy: PolicyConfig::default(),
            deploy: DeployConfig::default(),
            metadata: HashMap::new(),
        };

        self.write_manifest(&manifest)?;
        std::fs::write(self.root.join(entry), entry_content)?;

        let gitignore = r#"# CellScript
.cell/
build/
dist/
*.o
*.bin
"#;
        std::fs::write(self.root.join(".gitignore"), gitignore)?;

        Ok(())
    }

    pub fn add_dependency(&self, name: &str, version: &str) -> Result<()> {
        let mut manifest = self.read_manifest()?;

        manifest.dependencies.insert(name.to_string(), Dependency::Simple(version.to_string()));

        self.write_manifest(&manifest)?;
        Ok(())
    }

    pub fn remove_dependency(&self, name: &str) -> Result<()> {
        let mut manifest = self.read_manifest()?;
        manifest.dependencies.remove(name);
        self.write_manifest(&manifest)?;
        Ok(())
    }

    pub fn resolve_dependencies(&mut self) -> Result<()> {
        let manifest = self.read_manifest()?;

        for (name, dep) in &manifest.dependencies {
            self.resolve_dependency_from_root(name, dep, &self.root.clone(), &mut Vec::new())?;
        }

        Ok(())
    }

    fn resolve_dependency_from_root(&mut self, name: &str, dep: &Dependency, base_root: &Path, stack: &mut Vec<String>) -> Result<()> {
        if stack.iter().any(|item| item == name) {
            let mut cycle = stack.clone();
            cycle.push(name.to_string());
            return Err(CompileError::without_span(format!("Circular dependency detected: {}", cycle.join(" -> "))));
        }

        if self.resolved.contains_key(name) {
            return Ok(());
        }

        stack.push(name.to_string());

        let (resolved, child_dependencies) = match dep {
            Dependency::Simple(version) => (self.resolve_from_registry(name, version)?, HashMap::new()),
            Dependency::Detailed(detailed) => {
                if let Some(path) = &detailed.path {
                    let (resolved, manifest) = self.resolve_from_path_at(name, path, base_root)?;
                    (resolved, manifest.dependencies)
                } else if let Some(git) = &detailed.git {
                    let (resolved, manifest) = self.resolve_from_git_with_manifest(name, git, detailed)?;
                    (resolved, manifest.dependencies)
                } else {
                    (self.resolve_from_registry(name, &detailed.version)?, HashMap::new())
                }
            }
        };

        let package_root = resolved.path.clone();
        self.resolved.insert(name.to_string(), resolved);

        for (child_name, child_dep) in child_dependencies {
            self.resolve_dependency_from_root(&child_name, &child_dep, &package_root, stack)?;
        }

        stack.pop();
        Ok(())
    }

    pub fn resolve_from_registry(&self, name: &str, version: &str) -> Result<ResolvedPackage> {
        Err(CompileError::without_span(format!(
            "registry dependency '{}' with version '{}' is not supported yet; use a local path dependency",
            name, version
        )))
    }

    pub fn resolve_from_path(&self, name: &str, path: &str) -> Result<ResolvedPackage> {
        let (resolved, _) = self.resolve_from_path_at(name, path, &self.root)?;
        Ok(resolved)
    }

    fn resolve_from_path_at(&self, name: &str, path: &str, base_root: &Path) -> Result<(ResolvedPackage, PackageManifest)> {
        let package_path = base_root.join(path);
        let manifest_path = package_path.join("Cell.toml");

        if !manifest_path.exists() {
            return Err(CompileError::without_span(format!("Dependency '{}' not found at path '{}'", name, path)));
        }

        let content = std::fs::read_to_string(&manifest_path)?;
        let manifest: PackageManifest = toml::from_str(&content)?;

        let source_path = if base_root == self.root {
            PathBuf::from(path)
        } else {
            package_path.strip_prefix(&self.root).unwrap_or(&package_path).to_path_buf()
        };

        Ok((
            ResolvedPackage {
                name: name.to_string(),
                version: manifest.package.version.clone(),
                path: package_path,
                source: PackageSource::Local(source_path),
                dependencies: manifest.dependencies.keys().cloned().collect(),
            },
            manifest,
        ))
    }

    pub fn resolve_from_git(&self, name: &str, url: &str, detailed: &DetailedDependency) -> Result<ResolvedPackage> {
        let (resolved, _) = self.resolve_from_git_with_manifest(name, url, detailed)?;
        Ok(resolved)
    }

    fn resolve_from_git_with_manifest(
        &self,
        name: &str,
        url: &str,
        detailed: &DetailedDependency,
    ) -> Result<(ResolvedPackage, PackageManifest)> {
        let cache_dir = self.git_cache_dir();
        std::fs::create_dir_all(&cache_dir).map_err(|e| {
            CompileError::without_span(format!("failed to create git cache directory '{}': {}", cache_dir.display(), e))
        })?;

        let requested_ref = detailed.rev.as_ref().or(detailed.tag.as_ref()).or(detailed.branch.as_ref());
        let cache_key = format!("{}#{}", url, requested_ref.map(String::as_str).unwrap_or("HEAD"));
        let cache_name = format!("{}-{:016x}", name, simple_hash(&cache_key));
        let clone_dir = cache_dir.join(&cache_name);

        let git_result = if clone_dir.exists() && clone_dir.join(".git").exists() {
            Self::git_update(&clone_dir)
        } else {
            let _ = std::fs::remove_dir_all(&clone_dir);
            Self::git_clone(url, &clone_dir)
        };

        git_result.map_err(|e| CompileError::without_span(format!("git dependency '{}' from '{}' failed: {}", name, url, e)))?;

        if let Some(ref_str) = requested_ref {
            Self::git_checkout(&clone_dir, ref_str).map_err(|e| {
                CompileError::without_span(format!("git dependency '{}' failed to checkout '{}': {}", name, ref_str, e))
            })?;
        }

        let revision = Self::git_revision(&clone_dir).unwrap_or_else(|_| "unknown".to_string());

        let manifest_path = clone_dir.join("Cell.toml");
        if !manifest_path.exists() {
            return Err(CompileError::without_span(format!(
                "git dependency '{}' from '{}' does not contain Cell.toml at repository root",
                name, url
            )));
        }

        let content = std::fs::read_to_string(&manifest_path)?;
        let manifest: PackageManifest = toml::from_str(&content)?;

        Ok((
            ResolvedPackage {
                name: name.to_string(),
                version: manifest.package.version.clone(),
                path: clone_dir.clone(),
                source: PackageSource::Git { url: url.to_string(), revision },
                dependencies: manifest.dependencies.keys().cloned().collect(),
            },
            manifest,
        ))
    }

    fn git_cache_dir(&self) -> PathBuf {
        self.root.join(".cell/git-cache")
    }

    fn git_clone(url: &str, target: &Path) -> std::result::Result<(), String> {
        let output = std::process::Command::new("git")
            .args(["clone", url, &target.to_string_lossy()])
            .output()
            .map_err(|e| format!("failed to execute git: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("git clone failed: {}", stderr.trim()));
        }

        Ok(())
    }

    fn git_update(clone_dir: &Path) -> std::result::Result<(), String> {
        let output = std::process::Command::new("git")
            .args(["fetch", "--tags", "--prune", "origin"])
            .current_dir(clone_dir)
            .output()
            .map_err(|e| format!("failed to execute git: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!("Warning: git pull failed for {}: {}", clone_dir.display(), stderr.trim());
        }

        Ok(())
    }

    fn git_checkout(clone_dir: &Path, ref_str: &str) -> std::result::Result<(), String> {
        let _output = std::process::Command::new("git")
            .args(["fetch", "origin", ref_str])
            .current_dir(clone_dir)
            .output()
            .map_err(|e| format!("failed to execute git fetch: {}", e))?;

        let output = std::process::Command::new("git")
            .args(["checkout", ref_str])
            .current_dir(clone_dir)
            .output()
            .map_err(|e| format!("failed to execute git checkout: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("git checkout {} failed: {}", ref_str, stderr.trim()));
        }

        Ok(())
    }

    fn git_revision(clone_dir: &Path) -> std::result::Result<String, String> {
        let output = std::process::Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(clone_dir)
            .output()
            .map_err(|e| format!("failed to execute git rev-parse: {}", e))?;

        if !output.status.success() {
            return Err("git rev-parse failed".to_string());
        }

        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    pub fn get_resolved(&self) -> &HashMap<String, ResolvedPackage> {
        &self.resolved
    }

    pub fn build_dependency_graph(&self) -> DependencyGraph {
        let mut graph = DependencyGraph::new();

        for (name, package) in &self.resolved {
            graph.add_node(name.clone());
            for dep in &package.dependencies {
                graph.add_edge(name.clone(), dep.clone());
            }
        }

        graph
    }

    pub fn check_circular_deps(&self) -> Result<()> {
        let graph = self.build_dependency_graph();

        if let Some(cycle) = graph.find_cycle() {
            return Err(CompileError::without_span(format!("Circular dependency detected: {}", cycle.join(" -> "))));
        }

        Ok(())
    }

    pub fn get_source_paths(&self) -> Vec<PathBuf> {
        self.resolved.values().map(|p| p.path.join("src")).collect()
    }
}

pub struct DependencyGraph {
    nodes: Vec<String>,
    edges: HashMap<String, Vec<String>>,
}

impl Default for DependencyGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl DependencyGraph {
    pub fn new() -> Self {
        Self { nodes: Vec::new(), edges: HashMap::new() }
    }

    pub fn add_node(&mut self, name: String) {
        if !self.nodes.contains(&name) {
            self.nodes.push(name);
        }
    }

    pub fn add_edge(&mut self, from: String, to: String) {
        self.edges.entry(from).or_default().push(to);
    }

    pub fn find_cycle(&self) -> Option<Vec<String>> {
        let mut visited = HashMap::new();
        let mut rec_stack = Vec::new();

        for node in &self.nodes {
            if !visited.contains_key(node) {
                if let Some(cycle) = self.dfs_find_cycle(node, &mut visited, &mut rec_stack) {
                    return Some(cycle);
                }
            }
        }

        None
    }

    fn dfs_find_cycle(&self, node: &str, visited: &mut HashMap<String, bool>, rec_stack: &mut Vec<String>) -> Option<Vec<String>> {
        visited.insert(node.to_string(), true);
        rec_stack.push(node.to_string());

        if let Some(neighbors) = self.edges.get(node) {
            for neighbor in neighbors {
                if !visited.contains_key(neighbor) {
                    if let Some(cycle) = self.dfs_find_cycle(neighbor, visited, rec_stack) {
                        return Some(cycle);
                    }
                } else if rec_stack.contains(neighbor) {
                    let idx = rec_stack.iter().position(|n| n == neighbor).unwrap();
                    let mut cycle = rec_stack[idx..].to_vec();
                    cycle.push(neighbor.to_string());
                    return Some(cycle);
                }
            }
        }

        rec_stack.pop();
        None
    }
}

fn simple_hash(s: &str) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in s.bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lockfile {
    pub version: u32,
    pub dependencies: BTreeMap<String, LockedDependency>,
}

impl Lockfile {
    pub const CURRENT_VERSION: u32 = 1;

    pub fn new() -> Self {
        Self { version: Self::CURRENT_VERSION, dependencies: BTreeMap::new() }
    }

    pub fn read_from_root(root: &Path) -> Result<Option<Self>> {
        let lock_path = root.join("Cell.lock");
        if !lock_path.exists() {
            return Ok(None);
        }
        let content = std::fs::read_to_string(&lock_path)
            .map_err(|error| CompileError::without_span(format!("failed to read lockfile '{}': {}", lock_path.display(), error)))?;
        let lockfile = toml::from_str(&content)
            .map_err(|error| CompileError::without_span(format!("failed to parse lockfile '{}': {}", lock_path.display(), error)))?;
        Ok(Some(lockfile))
    }

    pub fn write_to_root(&self, root: &Path) -> Result<()> {
        let lock_path = root.join("Cell.lock");
        let content = toml::to_string_pretty(self)?;
        std::fs::write(&lock_path, content)?;
        Ok(())
    }

    pub fn update_from_resolved(&mut self, resolved: &HashMap<String, ResolvedPackage>) {
        for (name, package) in resolved {
            let locked = LockedDependency {
                version: package.version.clone(),
                source: match &package.source {
                    PackageSource::Local(path) => LockedSource::Path { path: path.to_string_lossy().to_string() },
                    PackageSource::Git { url, revision } => LockedSource::Git { url: url.clone(), revision: revision.clone() },
                    PackageSource::Registry { name: reg_name, version } => {
                        LockedSource::Registry { name: reg_name.clone(), version: version.clone() }
                    }
                },
            };
            self.dependencies.insert(name.clone(), locked);
        }
    }

    pub fn replace_with_resolved(&mut self, resolved: &HashMap<String, ResolvedPackage>) {
        self.dependencies.clear();
        self.update_from_resolved(resolved);
    }

    pub fn is_consistent(&self, manifest: &PackageManifest) -> bool {
        self.consistency_issues(manifest).is_empty()
    }

    pub fn consistency_issues(&self, manifest: &PackageManifest) -> Vec<String> {
        self.consistency_issues_with_expected(manifest, None)
    }

    pub fn consistency_issues_with_resolved(
        &self,
        manifest: &PackageManifest,
        resolved: &HashMap<String, ResolvedPackage>,
    ) -> Vec<String> {
        self.consistency_issues_with_expected(manifest, Some(resolved))
    }

    fn consistency_issues_with_expected(
        &self,
        manifest: &PackageManifest,
        resolved: Option<&HashMap<String, ResolvedPackage>>,
    ) -> Vec<String> {
        let mut issues = Vec::new();
        if self.version != Self::CURRENT_VERSION {
            issues.push(format!("Cell.lock version {} is not supported; expected {}", self.version, Self::CURRENT_VERSION));
        }

        for name in manifest.dependencies.keys() {
            let Some(locked) = self.dependencies.get(name) else {
                issues.push(format!("dependency '{}' is missing from Cell.lock", name));
                continue;
            };
            if let Some(dep) = manifest.dependencies.get(name) {
                issues.extend(lock_dependency_consistency_issues(name, dep, locked));
            }
        }

        if let Some(resolved) = resolved {
            for (name, package) in resolved {
                let Some(locked) = self.dependencies.get(name) else {
                    issues.push(format!("resolved dependency '{}' is missing from Cell.lock", name));
                    continue;
                };
                issues.extend(resolved_dependency_consistency_issues(name, package, locked));
            }
        }

        for name in self.dependencies.keys() {
            let expected_by_manifest = manifest.dependencies.contains_key(name);
            let expected_by_resolved = resolved.is_some_and(|resolved| resolved.contains_key(name));
            if !expected_by_manifest && !expected_by_resolved {
                issues.push(format!("Cell.lock contains stale dependency '{}' not present in Cell.toml", name));
            }
        }

        issues
    }
}

fn resolved_dependency_consistency_issues(name: &str, package: &ResolvedPackage, locked: &LockedDependency) -> Vec<String> {
    let mut issues = Vec::new();

    if locked.version != package.version {
        issues.push(format!(
            "resolved dependency '{}' has package version '{}' but Cell.lock records '{}'",
            name, package.version, locked.version
        ));
    }

    match (&package.source, &locked.source) {
        (PackageSource::Local(path), LockedSource::Path { path: locked_path }) if locked_path == path.to_string_lossy().as_ref() => {}
        (PackageSource::Git { url, revision }, LockedSource::Git { url: locked_url, revision: locked_revision })
            if locked_url == url && locked_revision == revision => {}
        (
            PackageSource::Registry { name: package_name, version: package_version },
            LockedSource::Registry { name: locked_name, version: locked_version },
        ) if locked_name == package_name && locked_version == package_version => {}
        (_, source) => issues.push(format!(
            "resolved dependency '{}' expects {} but Cell.lock records {}",
            name,
            package_source_display(&package.source),
            locked_source_display(source)
        )),
    }

    issues
}

fn lock_dependency_consistency_issues(name: &str, dep: &Dependency, locked: &LockedDependency) -> Vec<String> {
    let mut issues = Vec::new();

    match dep {
        Dependency::Simple(version) => match &locked.source {
            LockedSource::Registry { name: locked_name, version: locked_version }
                if locked_name == name && locked_version == version => {}
            source => issues.push(format!(
                "dependency '{}' expects registry source {}@{} but Cell.lock records {}",
                name,
                name,
                version,
                locked_source_display(source)
            )),
        },
        Dependency::Detailed(detail) => {
            if let Some(path) = &detail.path {
                match &locked.source {
                    LockedSource::Path { path: locked_path } if locked_path == path => {}
                    source => issues.push(format!(
                        "dependency '{}' expects path source '{}' but Cell.lock records {}",
                        name,
                        path,
                        locked_source_display(source)
                    )),
                }
                push_locked_version_issue(name, &detail.version, &locked.version, &mut issues);
            } else if let Some(git) = &detail.git {
                match &locked.source {
                    LockedSource::Git { url, revision } if url == git => {
                        if let Some(rev) = &detail.rev {
                            let rev_matches = revision == rev || revision.starts_with(rev) || rev.starts_with(revision);
                            if !rev_matches {
                                issues.push(format!(
                                    "dependency '{}' expects git revision '{}' but Cell.lock records '{}'",
                                    name, rev, revision
                                ));
                            }
                        }
                    }
                    source => issues.push(format!(
                        "dependency '{}' expects git source '{}' but Cell.lock records {}",
                        name,
                        git,
                        locked_source_display(source)
                    )),
                }
                push_locked_version_issue(name, &detail.version, &locked.version, &mut issues);
            } else {
                match &locked.source {
                    LockedSource::Registry { name: locked_name, version: locked_version }
                        if locked_name == name && locked_version == &detail.version => {}
                    source => issues.push(format!(
                        "dependency '{}' expects registry source {}@{} but Cell.lock records {}",
                        name,
                        name,
                        detail.version,
                        locked_source_display(source)
                    )),
                }
            }
        }
    }

    issues
}

fn push_locked_version_issue(name: &str, expected: &str, actual: &str, issues: &mut Vec<String>) {
    if expected != "*" && expected != actual {
        issues.push(format!("dependency '{}' expects package version '{}' but Cell.lock records '{}'", name, expected, actual));
    }
}

fn locked_source_display(source: &LockedSource) -> String {
    match source {
        LockedSource::Path { path } => format!("path '{}'", path),
        LockedSource::Git { url, revision } => format!("git '{}#{}'", url, revision),
        LockedSource::Registry { name, version } => format!("registry {}@{}", name, version),
    }
}

fn package_source_display(source: &PackageSource) -> String {
    match source {
        PackageSource::Local(path) => format!("path '{}'", path.display()),
        PackageSource::Git { url, revision } => format!("git '{}#{}'", url, revision),
        PackageSource::Registry { name, version } => format!("registry {}@{}", name, version),
    }
}

impl Default for Lockfile {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockedDependency {
    pub version: String,
    pub source: LockedSource,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LockedSource {
    Path { path: String },
    Git { url: String, revision: String },
    Registry { name: String, version: String },
}

pub mod version {
    use super::*;

    pub fn parse_version_req(req: &str) -> Result<VersionReq> {
        if req == "*" {
            return Ok(VersionReq::Any);
        }

        if let Some(stripped) = req.strip_prefix('^') {
            return Ok(VersionReq::Compatible(stripped.to_string()));
        }

        if let Some(stripped) = req.strip_prefix('=') {
            return Ok(VersionReq::Exact(stripped.to_string()));
        }

        if req.contains(',') || req.contains('>') || req.contains('<') {
            return Ok(VersionReq::Range(req.to_string()));
        }

        Ok(VersionReq::Compatible(req.to_string()))
    }

    pub fn satisfies(version: &str, req: &VersionReq) -> bool {
        match req {
            VersionReq::Any => true,
            VersionReq::Exact(v) => version == v,
            VersionReq::Compatible(v) => is_compatible(version, v),
            VersionReq::Range(r) => satisfies_range(version, r),
        }
    }

    fn is_compatible(version: &str, base: &str) -> bool {
        let v_parts: Vec<u32> = version.split('.').filter_map(|p| p.parse().ok()).collect();
        let b_parts: Vec<u32> = base.split('.').filter_map(|p| p.parse().ok()).collect();

        if v_parts.is_empty() || b_parts.is_empty() {
            return false;
        }

        if v_parts[0] != b_parts[0] {
            return false;
        }

        if v_parts[0] == 0 {
            if v_parts.len() < 2 || b_parts.len() < 2 {
                return false;
            }
            if v_parts[1] != b_parts[1] {
                return false;
            }
        }

        true
    }

    fn satisfies_range(_version: &str, _range: &str) -> bool {
        for clause in _range.split(',').map(str::trim).filter(|clause| !clause.is_empty()) {
            let Some((op, expected)) = parse_range_clause(clause) else {
                return false;
            };
            let Some(ordering) = compare_versions(_version, expected) else {
                return false;
            };
            let satisfied = match op {
                ">" => ordering.is_gt(),
                ">=" => ordering.is_gt() || ordering.is_eq(),
                "<" => ordering.is_lt(),
                "<=" => ordering.is_lt() || ordering.is_eq(),
                "=" | "==" => ordering.is_eq(),
                _ => false,
            };
            if !satisfied {
                return false;
            }
        }
        true
    }

    fn parse_range_clause(clause: &str) -> Option<(&str, &str)> {
        for op in [">=", "<=", "==", ">", "<", "="] {
            if let Some(version) = clause.strip_prefix(op) {
                return Some((op, version.trim()));
            }
        }
        None
    }

    fn compare_versions(left: &str, right: &str) -> Option<std::cmp::Ordering> {
        let left = parse_numeric_version(left)?;
        let right = parse_numeric_version(right)?;
        let max_len = left.len().max(right.len());
        for idx in 0..max_len {
            let lhs = *left.get(idx).unwrap_or(&0);
            let rhs = *right.get(idx).unwrap_or(&0);
            match lhs.cmp(&rhs) {
                std::cmp::Ordering::Equal => {}
                ordering => return Some(ordering),
            }
        }
        Some(std::cmp::Ordering::Equal)
    }

    fn parse_numeric_version(version: &str) -> Option<Vec<u32>> {
        let core = version.split_once('-').map(|(core, _)| core).unwrap_or(version);
        let parts: Option<Vec<u32>> = core.split('.').map(|part| part.parse().ok()).collect();
        let parts = parts?;
        if parts.is_empty() {
            None
        } else {
            Some(parts)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_manifest_serialization() {
        let manifest = PackageManifest {
            package: PackageInfo {
                name: "test".to_string(),
                version: "0.1.0".to_string(),
                authors: vec!["Test Author".to_string()],
                description: "Test package".to_string(),
                license: "MIT".to_string(),
                repository: String::new(),
                homepage: String::new(),
                documentation: String::new(),
                keywords: vec!["test".to_string()],
                categories: vec!["test".to_string()],
                cellscript_version: String::new(),
                entry: "src/main.cell".to_string(),
                source_roots: vec![],
                include: vec![],
                exclude: vec![],
            },
            dependencies: HashMap::new(),
            dev_dependencies: HashMap::new(),
            build: BuildConfig::default(),
            policy: PolicyConfig::default(),
            deploy: DeployConfig::default(),
            metadata: HashMap::new(),
        };

        let toml_str = toml::to_string(&manifest).unwrap();
        assert!(toml_str.contains("name = \"test\""));
        assert!(toml_str.contains("version = \"0.1.0\""));
    }

    #[test]
    fn test_dependency_graph() {
        let mut graph = DependencyGraph::new();
        graph.add_node("A".to_string());
        graph.add_node("B".to_string());
        graph.add_node("C".to_string());
        graph.add_edge("A".to_string(), "B".to_string());
        graph.add_edge("B".to_string(), "C".to_string());

        assert!(graph.find_cycle().is_none());

        graph.add_edge("C".to_string(), "A".to_string());
        assert!(graph.find_cycle().is_some());
    }

    #[test]
    fn test_version_compatibility() {
        assert!(version::satisfies("1.2.3", &VersionReq::Compatible("1.0.0".to_string())));
        assert!(version::satisfies("1.5.0", &VersionReq::Compatible("1.2.3".to_string())));
        assert!(!version::satisfies("2.0.0", &VersionReq::Compatible("1.0.0".to_string())));
        assert!(!version::satisfies("0.2.0", &VersionReq::Compatible("0.1.0".to_string())));
        assert!(version::satisfies("0.1.5", &VersionReq::Compatible("0.1.0".to_string())));
        assert!(version::satisfies("1.2.3", &VersionReq::Range(">=1.0.0, <2.0.0".to_string())));
        assert!(!version::satisfies("2.0.0", &VersionReq::Range(">=1.0.0, <2.0.0".to_string())));
        assert!(!version::satisfies("1.2.3", &VersionReq::Range(">=1.3.0".to_string())));
    }

    #[test]
    fn package_manager_resolves_local_path_dependencies() {
        let temp = tempdir().unwrap();
        let root = temp.path();
        std::fs::create_dir_all(root.join("deps/math/src")).unwrap();
        std::fs::write(
            root.join("Cell.toml"),
            r#"
[package]
name = "app"
version = "0.1.0"

[dependencies.math]
version = "0.1.0"
path = "deps/math"
"#,
        )
        .unwrap();
        std::fs::write(
            root.join("deps/math/Cell.toml"),
            r#"
[package]
name = "math"
version = "0.1.0"
"#,
        )
        .unwrap();

        let mut manager = PackageManager::new(root);
        manager.resolve_dependencies().unwrap();

        let math = manager.get_resolved().get("math").expect("path dependency should resolve");
        assert_eq!(math.name, "math");
        assert_eq!(math.version, "0.1.0");
        assert!(matches!(math.source, PackageSource::Local(_)));
        assert_eq!(manager.get_source_paths(), vec![root.join("deps/math/src")]);
    }

    #[test]
    fn package_manager_allows_path_dependency_without_version() {
        let temp = tempdir().unwrap();
        let root = temp.path();
        std::fs::create_dir_all(root.join("deps/math/src")).unwrap();
        std::fs::write(
            root.join("Cell.toml"),
            r#"
[package]
name = "app"
version = "0.1.0"

[dependencies.math]
path = "deps/math"
"#,
        )
        .unwrap();
        std::fs::write(
            root.join("deps/math/Cell.toml"),
            r#"
[package]
name = "math"
version = "0.2.0"
"#,
        )
        .unwrap();

        let mut manager = PackageManager::new(root);
        manager.resolve_dependencies().unwrap();

        let math = manager.get_resolved().get("math").expect("path dependency should resolve");
        assert_eq!(math.version, "0.2.0");
    }

    #[test]
    fn package_manager_resolves_transitive_local_path_dependencies() {
        let temp = tempdir().unwrap();
        let root = temp.path();
        std::fs::create_dir_all(root.join("deps/math/src")).unwrap();
        std::fs::create_dir_all(root.join("deps/util/src")).unwrap();
        std::fs::write(
            root.join("Cell.toml"),
            r#"
[package]
name = "app"
version = "0.1.0"

[dependencies.math]
version = "0.1.0"
path = "deps/math"
"#,
        )
        .unwrap();
        std::fs::write(
            root.join("deps/math/Cell.toml"),
            r#"
[package]
name = "math"
version = "0.1.0"

[dependencies.util]
version = "0.1.0"
path = "../util"
"#,
        )
        .unwrap();
        std::fs::write(
            root.join("deps/util/Cell.toml"),
            r#"
[package]
name = "util"
version = "0.1.0"
"#,
        )
        .unwrap();

        let mut manager = PackageManager::new(root);
        manager.resolve_dependencies().unwrap();

        assert!(manager.get_resolved().contains_key("math"));
        assert!(manager.get_resolved().contains_key("util"));
        assert_eq!(manager.get_resolved()["math"].dependencies, vec!["util"]);
    }

    #[test]
    fn package_manager_rejects_transitive_path_dependency_cycles() {
        let temp = tempdir().unwrap();
        let root = temp.path();
        std::fs::create_dir_all(root.join("deps/a/src")).unwrap();
        std::fs::create_dir_all(root.join("deps/b/src")).unwrap();
        std::fs::write(
            root.join("Cell.toml"),
            r#"
[package]
name = "app"
version = "0.1.0"

[dependencies.a]
path = "deps/a"
"#,
        )
        .unwrap();
        std::fs::write(
            root.join("deps/a/Cell.toml"),
            r#"
[package]
name = "a"
version = "0.1.0"

[dependencies.b]
path = "../b"
"#,
        )
        .unwrap();
        std::fs::write(
            root.join("deps/b/Cell.toml"),
            r#"
[package]
name = "b"
version = "0.1.0"

[dependencies.a]
path = "../a"
"#,
        )
        .unwrap();

        let mut manager = PackageManager::new(root);
        let error = manager.resolve_dependencies().unwrap_err();

        assert!(error.message.contains("Circular dependency detected"), "{}", error.message);
        assert!(error.message.contains("a -> b -> a"), "{}", error.message);
    }

    #[test]
    fn lockfile_consistency_reports_stale_and_mismatched_path_sources() {
        let manifest: PackageManifest = toml::from_str(
            r#"
[package]
name = "app"
version = "0.1.0"

[dependencies.math]
version = "0.1.0"
path = "deps/math"
"#,
        )
        .unwrap();
        let mut lockfile = Lockfile::new();
        lockfile.dependencies.insert(
            "math".to_string(),
            LockedDependency { version: "0.2.0".to_string(), source: LockedSource::Path { path: "deps/old-math".to_string() } },
        );
        lockfile.dependencies.insert(
            "stale".to_string(),
            LockedDependency {
                version: "1.0.0".to_string(),
                source: LockedSource::Registry { name: "stale".to_string(), version: "1.0.0".to_string() },
            },
        );

        let issues = lockfile.consistency_issues(&manifest);

        assert!(issues.iter().any(|issue| issue.contains("expects path source 'deps/math'")), "{issues:?}");
        assert!(issues.iter().any(|issue| issue.contains("expects package version '0.1.0'")), "{issues:?}");
        assert!(issues.iter().any(|issue| issue.contains("stale dependency 'stale'")), "{issues:?}");
        assert!(!lockfile.is_consistent(&manifest));
    }

    #[test]
    fn lockfile_consistency_allows_resolved_transitive_path_dependencies() {
        let manifest: PackageManifest = toml::from_str(
            r#"
[package]
name = "app"
version = "0.1.0"

[dependencies.math]
version = "0.1.0"
path = "deps/math"
"#,
        )
        .unwrap();
        let mut lockfile = Lockfile::new();
        lockfile.dependencies.insert(
            "math".to_string(),
            LockedDependency { version: "0.1.0".to_string(), source: LockedSource::Path { path: "deps/math".to_string() } },
        );
        lockfile.dependencies.insert(
            "util".to_string(),
            LockedDependency { version: "0.1.0".to_string(), source: LockedSource::Path { path: "deps/math/../util".to_string() } },
        );
        let mut resolved = HashMap::new();
        resolved.insert(
            "math".to_string(),
            ResolvedPackage {
                name: "math".to_string(),
                version: "0.1.0".to_string(),
                path: PathBuf::from("deps/math"),
                source: PackageSource::Local(PathBuf::from("deps/math")),
                dependencies: vec!["util".to_string()],
            },
        );
        resolved.insert(
            "util".to_string(),
            ResolvedPackage {
                name: "util".to_string(),
                version: "0.1.0".to_string(),
                path: PathBuf::from("deps/util"),
                source: PackageSource::Local(PathBuf::from("deps/math/../util")),
                dependencies: Vec::new(),
            },
        );

        let issues = lockfile.consistency_issues_with_resolved(&manifest, &resolved);

        assert!(issues.is_empty(), "{issues:?}");
    }

    #[test]
    fn lockfile_replace_with_resolved_prunes_removed_dependencies() {
        let mut lockfile = Lockfile::new();
        lockfile.dependencies.insert(
            "old".to_string(),
            LockedDependency {
                version: "1.0.0".to_string(),
                source: LockedSource::Registry { name: "old".to_string(), version: "1.0.0".to_string() },
            },
        );

        let mut resolved = HashMap::new();
        resolved.insert(
            "math".to_string(),
            ResolvedPackage {
                name: "math".to_string(),
                version: "0.1.0".to_string(),
                path: PathBuf::from("deps/math"),
                source: PackageSource::Local(PathBuf::from("deps/math")),
                dependencies: Vec::new(),
            },
        );

        lockfile.replace_with_resolved(&resolved);

        assert!(lockfile.dependencies.contains_key("math"));
        assert!(!lockfile.dependencies.contains_key("old"));
    }

    #[test]
    fn lockfile_read_from_root_rejects_malformed_lockfiles() {
        let temp = tempdir().unwrap();
        std::fs::write(temp.path().join("Cell.lock"), "not = [valid").unwrap();

        let error = Lockfile::read_from_root(temp.path()).unwrap_err();

        assert!(error.message.contains("failed to parse lockfile"), "{}", error.message);
    }

    #[test]
    fn package_manager_rejects_registry_dependencies_fail_closed() {
        let temp = tempdir().unwrap();
        std::fs::write(
            temp.path().join("Cell.toml"),
            r#"
[package]
name = "app"
version = "0.1.0"

[dependencies]
remote = "1.2.3"
"#,
        )
        .unwrap();

        let mut manager = PackageManager::new(temp.path());
        let error = manager.resolve_dependencies().unwrap_err();

        assert!(error.message.contains("registry dependency 'remote'"));
        assert!(error.message.contains("not supported yet"));
        assert!(error.message.contains("local path dependency"));
        assert!(manager.get_resolved().is_empty());
    }

    #[test]
    fn package_manager_git_dependency_fails_for_invalid_url() {
        let temp = tempdir().unwrap();
        std::fs::write(
            temp.path().join("Cell.toml"),
            r#"
[package]
name = "app"
version = "0.1.0"

[dependencies.remote]
version = "0.1.0"
git = "https://example.invalid/remote.git"
rev = "abc123"
"#,
        )
        .unwrap();

        let mut manager = PackageManager::new(temp.path());
        let error = manager.resolve_dependencies().unwrap_err();

        assert!(error.message.contains("remote"));
        assert!(error.message.contains("https://example.invalid/remote.git"));
        assert!(manager.get_resolved().is_empty());
    }
}
