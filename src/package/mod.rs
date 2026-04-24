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
                entry: "src/main.cell".to_string(),
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

        let main_content = format!(
            r#"module {};

// Entry point for {}
"#,
            name, name
        );
        std::fs::write(self.root.join("src/main.cell"), main_content)?;

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
            self.resolve_dependency(name, dep)?;
        }

        Ok(())
    }

    fn resolve_dependency(&mut self, name: &str, dep: &Dependency) -> Result<()> {
        if self.resolved.contains_key(name) {
            return Ok(());
        }

        let resolved = match dep {
            Dependency::Simple(version) => self.resolve_from_registry(name, version)?,
            Dependency::Detailed(detailed) => {
                if let Some(path) = &detailed.path {
                    self.resolve_from_path(name, path)?
                } else if let Some(git) = &detailed.git {
                    self.resolve_from_git(name, git, detailed)?
                } else {
                    self.resolve_from_registry(name, &detailed.version)?
                }
            }
        };

        self.resolved.insert(name.to_string(), resolved);
        Ok(())
    }

    pub fn resolve_from_registry(&self, name: &str, version: &str) -> Result<ResolvedPackage> {
        Err(CompileError::without_span(format!(
            "registry dependency '{}' with version '{}' is not supported yet; use a local path dependency",
            name, version
        )))
    }

    pub fn resolve_from_path(&self, name: &str, path: &str) -> Result<ResolvedPackage> {
        let package_path = self.root.join(path);
        let manifest_path = package_path.join("Cell.toml");

        if !manifest_path.exists() {
            return Err(CompileError::without_span(format!("Dependency '{}' not found at path '{}'", name, path)));
        }

        let content = std::fs::read_to_string(&manifest_path)?;
        let manifest: PackageManifest = toml::from_str(&content)?;

        Ok(ResolvedPackage {
            name: name.to_string(),
            version: manifest.package.version,
            path: package_path,
            source: PackageSource::Local(PathBuf::from(path)),
            dependencies: manifest.dependencies.keys().cloned().collect(),
        })
    }

    pub fn resolve_from_git(&self, name: &str, url: &str, detailed: &DetailedDependency) -> Result<ResolvedPackage> {
        let cache_dir = self.git_cache_dir();
        std::fs::create_dir_all(&cache_dir).map_err(|e| {
            CompileError::without_span(format!("failed to create git cache directory '{}': {}", cache_dir.display(), e))
        })?;

        let cache_name = format!("{}-{:016x}", name, simple_hash(url));
        let clone_dir = cache_dir.join(&cache_name);

        let git_result = if clone_dir.exists() && clone_dir.join(".git").exists() {
            Self::git_update(&clone_dir)
        } else {
            let _ = std::fs::remove_dir_all(&clone_dir);
            Self::git_clone(url, &clone_dir)
        };

        git_result.map_err(|e| CompileError::without_span(format!("git dependency '{}' from '{}' failed: {}", name, url, e)))?;

        if let Some(ref_str) = detailed.rev.as_ref().or(detailed.tag.as_ref()).or(detailed.branch.as_ref()) {
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

        Ok(ResolvedPackage {
            name: name.to_string(),
            version: manifest.package.version.clone(),
            path: clone_dir.clone(),
            source: PackageSource::Git { url: url.to_string(), revision },
            dependencies: manifest.dependencies.keys().cloned().collect(),
        })
    }

    fn git_cache_dir(&self) -> PathBuf {
        self.root.join(".cell/git-cache")
    }

    fn git_clone(url: &str, target: &Path) -> std::result::Result<(), String> {
        let output = std::process::Command::new("git")
            .args(["clone", "--depth", "1", url, &target.to_string_lossy()])
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
            .args(["pull", "--ff-only"])
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
            .args(["rev-parse", "--short", "HEAD"])
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

    pub fn read_from_root(root: &Path) -> Option<Self> {
        let lock_path = root.join("Cell.lock");
        if !lock_path.exists() {
            return None;
        }
        let content = std::fs::read_to_string(&lock_path).ok()?;
        toml::from_str(&content).ok()
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

        for name in self.dependencies.keys() {
            if !manifest.dependencies.contains_key(name) {
                issues.push(format!("Cell.lock contains stale dependency '{}' not present in Cell.toml", name));
            }
        }

        issues
    }
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
        true
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
