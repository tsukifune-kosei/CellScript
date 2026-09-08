use crate::artifact::{validate_declarations, ArtifactDeclaration};
use crate::edition::{CellScriptEdition, CURRENT_EDITION};
use crate::error::{CompileError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub mod registry;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageManifest {
    pub package: PackageInfo,
    #[serde(default)]
    pub workspace: Option<WorkspaceConfig>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<ArtifactDeclaration>,
    #[serde(default)]
    pub dependencies: HashMap<String, Dependency>,
    #[serde(default)]
    pub dev_dependencies: HashMap<String, Dependency>,
    #[serde(default)]
    pub features: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub environments: BTreeMap<String, CkbEnvironment>,
    #[serde(default)]
    pub dependency_overrides: BTreeMap<String, BTreeMap<String, Dependency>>,
    #[serde(default)]
    pub resolvers: BTreeMap<String, ResolverConfig>,
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
    pub edition: CellScriptEdition,
    #[serde(default)]
    pub namespace: Option<String>,
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
    /// SemVer requirement for the CellScript compiler that may load this
    /// package. Omission preserves legacy packages as unconstrained; newly
    /// created packages record an explicit minimum.
    #[serde(default = "default_compiler_requirement")]
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

fn default_compiler_requirement() -> String {
    "*".to_string()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WorkspaceConfig {
    #[serde(default)]
    pub members: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
}

/// A virtual manifest that contains only a `[workspace]` section with no `[package]`.
/// This represents a workspace root that is not itself a package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceManifest {
    pub workspace: WorkspaceConfig,
}

impl WorkspaceManifest {
    pub fn read_from_dir(dir: &Path) -> Result<Option<Self>> {
        let manifest_path = dir.join("Cell.toml");
        if !manifest_path.exists() {
            return Ok(None);
        }
        let content = std::fs::read_to_string(&manifest_path)
            .map_err(|e| CompileError::without_span(format!("failed to read '{}': {}", manifest_path.display(), e)))?;
        // Try parsing as a workspace-only manifest first.
        let ws: std::result::Result<WorkspaceManifest, _> = toml::from_str(&content);
        if let Ok(manifest) = ws {
            // Make sure it really has no [package] section — if it does,
            // the caller should use PackageManifest instead.
            if !content.contains("[package]") {
                return Ok(Some(manifest));
            }
        }
        Ok(None)
    }

    pub fn write_to_dir(&self, dir: &Path) -> Result<()> {
        let manifest_path = dir.join("Cell.toml");
        let content = toml::to_string_pretty(self)?;
        std::fs::write(&manifest_path, content)?;
        Ok(())
    }

    /// Resolve member paths relative to the workspace root directory.
    pub fn resolve_member_paths(&self, root: &Path) -> Result<Vec<PathBuf>> {
        let mut members = Vec::new();
        for member_pattern in &self.workspace.members {
            let member_path = root.join(member_pattern);
            if member_path.is_dir() && member_path.join("Cell.toml").exists() {
                members.push(canonical_path(&member_path)?);
            } else {
                return Err(CompileError::without_span(format!(
                    "workspace member '{}' does not exist or is not a valid package directory",
                    member_pattern
                )));
            }
        }
        Ok(members)
    }
}

fn canonical_path(path: &Path) -> Result<PathBuf> {
    std::fs::canonicalize(path).map_err(|e| CompileError::without_span(format!("failed to canonicalize '{}': {}", path.display(), e)))
}

fn relative_path(from: &Path, to: &Path) -> Option<PathBuf> {
    let from_components: Vec<_> = from.components().collect();
    let to_components: Vec<_> = to.components().collect();
    let common = from_components.iter().zip(&to_components).take_while(|(left, right)| left == right).count();
    if common == 0 {
        return None;
    }
    let mut relative = PathBuf::new();
    for _ in common..from_components.len() {
        relative.push("..");
    }
    for component in &to_components[common..] {
        relative.push(component.as_os_str());
    }
    Some(if relative.as_os_str().is_empty() { PathBuf::from(".") } else { relative })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
// Keep the public manifest API and untagged TOML representation source-compatible;
// boxing Detailed would force every programmatic manifest author to wrap it.
#[allow(clippy::large_enum_variant)]
pub enum Dependency {
    Simple(String),
    Detailed(DetailedDependency),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetailedDependency {
    #[serde(default = "default_any_version")]
    pub version: String,
    #[serde(default)]
    pub namespace: Option<String>,
    /// Declared package name when the dependency's local alias differs.
    #[serde(default)]
    pub package: Option<String>,
    /// Name of a bounded external resolver declared in `[resolvers.<name>]`.
    /// It is invoked only by explicit lock/update operations and is normalized
    /// to an ordinary immutable Registry or Git source before Cell.lock is written.
    #[serde(default)]
    pub resolver: Option<String>,
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
    /// Explicit dependency-local environment name for this edge. The selected
    /// environment must have the same CKB chain identity as the root package.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub use_environment: Option<String>,
    /// Declare that this dependency edge does not apply a dependency-local
    /// environment override. The root chain identity is still preserved for
    /// the dependency's transitive edges and external resolver requests.
    #[serde(default, skip_serializing_if = "is_false")]
    pub environment_independent: bool,
    /// Persisted acknowledgement that this dependency may resolve from a
    /// source_published or indexed_pending Registry entry.
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_unverified: bool,
    /// Persisted incident-review acknowledgement for quarantined entries.
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_quarantined: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolverConfig {
    pub command: String,
    pub sha256: String,
    #[serde(default)]
    pub args: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ExternalResolverRequest<'a> {
    schema: &'static str,
    alias: &'a str,
    package: &'a str,
    version_requirement: &'a str,
    environment: Option<ExternalResolverEnvironment<'a>>,
}

#[derive(Debug, Serialize)]
struct ExternalResolverEnvironment<'a> {
    root_name: &'a str,
    local_name: Option<&'a str>,
    chain_id: &'a str,
    genesis_hash: &'a str,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalResolverResponse {
    schema: String,
    dependency: ExternalResolvedDependency,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalResolvedDependency {
    package: String,
    version: String,
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    git: Option<String>,
    #[serde(default)]
    rev: Option<String>,
}

const EXTERNAL_RESOLVER_REQUEST_SCHEMA: &str = "cellscript-dependency-resolver-request-v2";
const EXTERNAL_RESOLVER_RESPONSE_SCHEMA: &str = "cellscript-dependency-resolver-response-v1";
const EXTERNAL_RESOLVER_TIMEOUT: Duration = Duration::from_secs(10);
const EXTERNAL_RESOLVER_MAX_OUTPUT_BYTES: u64 = 1024 * 1024;

fn is_false(value: &bool) -> bool {
    !*value
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
    pub deny_ckb_runtime: bool,
    #[serde(default)]
    pub deny_runtime_obligations: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeployConfig {
    #[serde(default)]
    pub ckb: Option<CkbDeployConfig>,
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
    #[serde(default)]
    pub trusted_external_verifiers: Vec<CkbTrustedExternalVerifierConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CkbTrustedExternalVerifierConfig {
    pub schema: String,
    pub name: String,
    pub scope: String,
    pub operation: String,
    pub adapter: String,
    pub code_hash: String,
    pub hash_type: String,
    pub source_identity: String,
    pub applicability: String,
    pub trust_basis: String,
    pub guarantees: Vec<String>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CkbEnvironment {
    pub chain_id: String,
    pub genesis_hash: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DependencyScope {
    Runtime,
    Test,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionOptions {
    pub scope: DependencyScope,
    pub features: BTreeSet<String>,
    pub all_features: bool,
    pub no_default_features: bool,
    pub environment: Option<String>,
    pub offline: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EnvironmentSelectionPolicy {
    Root,
    InheritByChainIdentity,
    ExplicitLocalName,
    EnvironmentIndependent,
}

impl EnvironmentSelectionPolicy {
    fn as_str(self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::InheritByChainIdentity => "inherit-by-chain-identity",
            Self::ExplicitLocalName => "explicit-local-name",
            Self::EnvironmentIndependent => "environment-independent",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SelectedEnvironmentContext {
    root_name: String,
    local_name: Option<String>,
    chain_id: String,
    genesis_hash: String,
    policy: EnvironmentSelectionPolicy,
}

impl Default for ResolutionOptions {
    fn default() -> Self {
        Self {
            scope: DependencyScope::Runtime,
            features: BTreeSet::new(),
            all_features: false,
            no_default_features: false,
            environment: None,
            offline: false,
        }
    }
}

thread_local! {
    static RESOLUTION_OPTIONS_STACK: RefCell<Vec<ResolutionOptions>> = const { RefCell::new(Vec::new()) };
}

pub fn with_resolution_options<T>(options: ResolutionOptions, operation: impl FnOnce() -> T) -> T {
    RESOLUTION_OPTIONS_STACK.with(|stack| stack.borrow_mut().push(options));
    struct PopResolutionOptions;
    impl Drop for PopResolutionOptions {
        fn drop(&mut self) {
            RESOLUTION_OPTIONS_STACK.with(|stack| {
                stack.borrow_mut().pop();
            });
        }
    }
    let _guard = PopResolutionOptions;
    operation()
}

pub(crate) fn active_resolution_options(scope: DependencyScope) -> ResolutionOptions {
    RESOLUTION_OPTIONS_STACK.with(|stack| {
        let mut options = stack.borrow().last().cloned().unwrap_or_default();
        options.scope = scope;
        options
    })
}

pub struct PackageManager {
    root: PathBuf,
    resolved: BTreeMap<String, ResolvedPackage>,
    root_dependencies: BTreeMap<String, String>,
    selected_coordinates: BTreeMap<PackageCoordinate, SelectedPackageInstance>,
}

#[derive(Debug, Clone)]
pub struct ResolvedPackage {
    pub node_id: String,
    pub name: String,
    pub version: String,
    pub path: PathBuf,
    pub source: PackageSource,
    pub dependencies: BTreeMap<String, String>,
    pub namespace: Option<String>,
    pub source_hash: Option<String>,
    pub manifest_digest: String,
    pub compiler_requirement: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PackageCoordinate {
    namespace: Option<String>,
    name: String,
}

impl PackageCoordinate {
    fn from_package(package: &ResolvedPackage) -> Self {
        Self { namespace: package.namespace.clone(), name: package.name.clone() }
    }

    fn display(&self) -> String {
        self.namespace.as_deref().map_or_else(|| self.name.clone(), |namespace| format!("{namespace}/{}", self.name))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FeatureSelection {
    features: BTreeSet<String>,
    all_features: bool,
    default_features: bool,
}

impl FeatureSelection {
    fn from_options(options: &ResolutionOptions) -> Self {
        Self { features: options.features.clone(), all_features: options.all_features, default_features: !options.no_default_features }
    }

    fn labels(&self) -> Vec<String> {
        let mut labels = self.features.iter().cloned().collect::<Vec<_>>();
        if self.all_features {
            labels.push("*".to_string());
        }
        if self.default_features {
            labels.push("default".to_string());
        }
        labels.sort();
        labels
    }
}

#[derive(Debug, Clone)]
struct IncomingPackageRequest {
    parent_package: String,
    alias: String,
    version_requirement: Option<String>,
    candidate_version: String,
    candidate_source: String,
    features: FeatureSelection,
    environment: Option<String>,
}

#[derive(Debug, Clone)]
struct SelectedPackageInstance {
    node_id: String,
    version: String,
    manifest_digest: String,
    compiler_requirement: String,
    source_authority: String,
    source_identity: String,
    source_is_registry: bool,
    features: FeatureSelection,
    environment: Option<String>,
    incoming: Vec<IncomingPackageRequest>,
}

/// Emit yank-related notices to stderr during registry resolution.
///
/// The registry resolver never silently picks a yanked version for a range
/// request (yanked entries are filtered out by `find_matching_version`). A
/// yanked version can only be reached when the caller pins it explicitly (for
/// example via an `=x.y.z` exact requirement or a lockfile that names it). In
/// that case we warn and suggest the latest non-yanked version, honouring the
/// Phase 1 contract that resolving a yanked version is surfaced to the user
/// rather than failing or passing silently.
fn emit_yank_notices(namespace: &str, name: &str, requested: &str, selected: &str, index: &registry::RegistryIndex) {
    let Some(entry) = index.versions.iter().find(|v| v.version == selected) else {
        return;
    };
    if !entry.yanked {
        return;
    }
    // Prefer the publisher-declared replacement (`replaced_by`) when present;
    // otherwise fall back to the latest non-yanked version.
    let suggestion = entry.replaced_by.clone().or_else(|| {
        index
            .versions
            .iter()
            .filter(|v| !v.yanked && v.version != selected)
            .map(|v| v.version.clone())
            .max_by(|a, b| compare_semver(a, b))
    });
    let reason = entry.yanked_reason.as_deref().map(|r| format!(" (reason: {})", r)).unwrap_or_default();
    match suggestion {
        Some(v) => eprintln!(
            "warning: {}/{}@{} resolves to yanked version {}{}; consider upgrading to {}",
            namespace, name, requested, selected, reason, v
        ),
        None => eprintln!(
            "warning: {}/{}@{} resolves to yanked version {}{} with no non-yanked alternative published",
            namespace, name, requested, selected, reason
        ),
    }
}

fn registry_resolution_blocked_error(
    namespace: &str,
    name: &str,
    requested: &str,
    version: &registry::RegistryVersion,
    policy: registry::RegistryResolutionPolicy,
) -> CompileError {
    let reason = version
        .resolver_block_reason(policy, matches!(crate::package::version::parse_version_req(requested), Ok(VersionReq::Exact(_))));
    let status = version.effective_status();
    let hint = match reason {
        Some("unverified") => "use --allow-unverified for an explicit direct install, or wait until the entry reaches verified_build",
        Some("quarantined") => "use --allow-quarantined only for an explicit incident-review install",
        Some("deprecated") => "pin the version exactly or select a non-deprecated replacement",
        Some("yanked") => "pin the version exactly or select a non-yanked replacement",
        _ => "select a version that is eligible for default registry resolution",
    };

    CompileError::without_span(format!(
        "registry package '{}/{}@{}' matched version '{}' but status '{}' is not eligible for default resolution; {}",
        namespace,
        name,
        requested,
        version.version,
        status.as_str(),
        hint
    ))
}

fn compare_semver(left: &str, right: &str) -> std::cmp::Ordering {
    match (semver::Version::parse(left), semver::Version::parse(right)) {
        (Ok(left), Ok(right)) => left.cmp(&right),
        (Ok(_), Err(_)) => std::cmp::Ordering::Greater,
        (Err(_), Ok(_)) => std::cmp::Ordering::Less,
        (Err(_), Err(_)) => left.cmp(right),
    }
}

#[derive(Debug, Clone)]
pub enum PackageSource {
    Local(PathBuf),
    Git { url: String, revision: String },
    Registry { registry: String, url: String, revision: String, namespace: String, version: String },
}

fn package_source_authority(package: &ResolvedPackage) -> String {
    match &package.source {
        PackageSource::Local(path) => format!("path:{}", path.to_string_lossy().replace('\\', "/")),
        PackageSource::Git { url, .. } => format!("git:{url}"),
        PackageSource::Registry { registry, namespace, .. } => format!("registry:{registry}:{namespace}/{}", package.name),
    }
}

fn package_source_identity(package: &ResolvedPackage) -> String {
    match &package.source {
        PackageSource::Local(path) => format!("path:{}", path.to_string_lossy().replace('\\', "/")),
        PackageSource::Git { url, revision } => format!("git:{url}#{revision}"),
        PackageSource::Registry { registry, url, revision, namespace, version } => {
            format!("registry:{registry}:{namespace}/{}@{version}#{revision}:{url}", package.name)
        }
    }
}

fn dependency_requirement_for_diagnostic(dependency: &Dependency) -> Option<String> {
    match dependency {
        Dependency::Simple(requirement) => Some(requirement.clone()),
        Dependency::Detailed(detail) if !detail.version.trim().is_empty() => Some(detail.version.clone()),
        Dependency::Detailed(_) => None,
    }
}

fn incoming_package_request_json(request: &IncomingPackageRequest) -> serde_json::Value {
    serde_json::json!({
        "from_package": request.parent_package,
        "alias": request.alias,
        "version_requirement": request.version_requirement,
        "candidate_version": request.candidate_version,
        "candidate_source": request.candidate_source,
        "features": request.features.labels(),
        "environment": request.environment,
    })
}

#[derive(Debug, Clone)]
pub enum VersionReq {
    Exact(String),
    Compatible(String),
    Range(String),
    Any,
}

fn manifest_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

pub fn compute_manifest_digest(root: &Path) -> Result<String> {
    let path = root.join("Cell.toml");
    let bytes = std::fs::read(&path)
        .map_err(|error| CompileError::without_span(format!("failed to read manifest '{}': {}", path.display(), error)))?;
    Ok(manifest_digest(&bytes))
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex::encode(digest.finalize()))
}

fn read_bounded_resolver_output(path: &Path) -> Result<Vec<u8>> {
    let metadata = std::fs::metadata(path)?;
    if metadata.len() > EXTERNAL_RESOLVER_MAX_OUTPUT_BYTES {
        return Err(CompileError::without_span(format!("external resolver output '{}' exceeds 1 MiB", path.display())));
    }
    Ok(std::fs::read(path)?)
}

fn sanitize_node_component(value: &str) -> String {
    value
        .chars()
        .map(|character| if character.is_ascii_alphanumeric() || character == '-' || character == '_' { character } else { '_' })
        .take(80)
        .collect()
}

fn package_node_id(
    package: &ResolvedPackage,
    options: &ResolutionOptions,
    environment: Option<&SelectedEnvironmentContext>,
) -> String {
    let source = match &package.source {
        PackageSource::Local(path) => format!("path:{}", path.to_string_lossy().replace('\\', "/")),
        PackageSource::Git { url, revision } => format!("git:{url}#{revision}"),
        PackageSource::Registry { registry, namespace, version, revision, .. } => {
            format!("registry:{registry}:{namespace}/{}@{version}#{revision}", package.name)
        }
    };
    let mut features: Vec<_> = options.features.iter().cloned().collect();
    if options.all_features {
        features.push("*".to_string());
    }
    if !options.no_default_features {
        features.push("default".to_string());
    }
    features.sort();
    let environment = environment.map(environment_node_identity).unwrap_or_else(|| "default".to_string());
    format!(
        "{}@{}|{}|compiler={}|env={}|features={}",
        package.name,
        package.version,
        source,
        hex::encode(package.compiler_requirement.as_bytes()),
        environment,
        features.join(",")
    )
}

/// Parse the public `[package].cellscript_version` compatibility contract.
///
/// Existing manifests used bare versions such as `0.16` to mean the minimum
/// compiler generation they were written for. Preserve that meaning by
/// normalising a bare version to `>=version`; explicit operators use standard
/// SemVer requirement syntax.
pub fn parse_compiler_requirement(requirement: &str) -> Result<semver::VersionReq> {
    let requirement = requirement.trim();
    if requirement.is_empty() {
        return Err(CompileError::without_span(
            "package cellscript_version must not be empty; omit it for an unconstrained legacy package or use a SemVer requirement",
        )
        .with_code("E2600"));
    }
    let normalized = if requirement == "*"
        || requirement.chars().any(|character| matches!(character, '<' | '>' | '=' | '^' | '~' | '*' | ',' | '|'))
    {
        requirement.to_string()
    } else {
        format!(">={requirement}")
    };
    semver::VersionReq::parse(&normalized).map_err(|error| {
        CompileError::without_span(format!("invalid package cellscript_version requirement '{}': {error}", requirement))
            .with_code("E2600")
    })
}

pub fn compiler_requirement_matches(requirement: &str, compiler_version: &str) -> Result<bool> {
    let requirement = parse_compiler_requirement(requirement)?;
    let compiler_version = semver::Version::parse(compiler_version).map_err(|error| {
        CompileError::without_span(format!("active CellScript compiler version '{compiler_version}' is not valid SemVer: {error}"))
            .with_code("E2600")
    })?;
    Ok(requirement.matches(&compiler_version))
}

pub fn validate_package_compiler_requirement(package: &PackageInfo) -> Result<()> {
    if compiler_requirement_matches(&package.cellscript_version, crate::VERSION)? {
        return Ok(());
    }
    Err(CompileError::without_span(format!(
        "package '{}@{}' requires CellScript compiler '{}', but active cellc is '{}'; select a compatible package/compiler version before loading source",
        package.name, package.version, package.cellscript_version, crate::VERSION
    ))
    .with_code("E2600")
    .with_details(serde_json::json!({
        "package": package.name,
        "package_version": package.version,
        "compiler_requirement": package.cellscript_version,
        "active_compiler_version": crate::VERSION,
        "phase": "manifest-before-source",
    })))
}

fn compiler_error_with_incoming_edge(mut error: CompileError, parent_package: &str, alias: &str, package: &str) -> CompileError {
    if error.code.as_deref() != Some("E2600") {
        return error;
    }
    let mut details = error.details.take().and_then(|value| value.as_object().cloned()).unwrap_or_default();
    details.entry("package".to_string()).or_insert_with(|| serde_json::Value::String(package.to_string()));
    details.insert(
        "incoming_edge".to_string(),
        serde_json::json!({
            "from_package": parent_package,
            "alias": alias,
            "to_package": package,
        }),
    );
    error.details = Some(serde_json::Value::Object(details));
    error
}

fn aggregate_compiler_incompatibilities(errors: Vec<CompileError>) -> CompileError {
    let entries = errors
        .iter()
        .map(|error| {
            let mut entry = error.details.clone().unwrap_or_else(|| serde_json::json!({}));
            if let Some(object) = entry.as_object_mut() {
                object.insert("message".to_string(), serde_json::Value::String(error.message.clone()));
            }
            entry
        })
        .collect::<Vec<_>>();
    let packages =
        entries.iter().filter_map(|entry| entry.get("package").and_then(serde_json::Value::as_str)).collect::<Vec<_>>().join(", ");
    CompileError::without_span(format!(
        "{} package compiler requirement(s) are incompatible with cellc {}: {}",
        errors.len(),
        crate::VERSION,
        packages
    ))
    .with_code("E2600")
    .with_details(serde_json::json!({
        "active_compiler_version": crate::VERSION,
        "phase": "dependency-compatibility-preflight",
        "incompatible_packages": entries,
    }))
    .with_related(errors)
}

fn environment_node_identity(environment: &SelectedEnvironmentContext) -> String {
    let local_name = environment.local_name.as_deref().map(hex::encode).unwrap_or_else(|| "-".to_string());
    format!(
        "{}:root={}:local={}:chain={}:genesis={}",
        environment.policy.as_str(),
        hex::encode(environment.root_name.as_bytes()),
        local_name,
        hex::encode(environment.chain_id.as_bytes()),
        environment.genesis_hash
    )
}

fn dependency_package_name(alias: &str, dependency: &Dependency) -> String {
    match dependency {
        Dependency::Detailed(detail) => detail.package.clone().unwrap_or_else(|| alias.to_string()),
        Dependency::Simple(_) => alias.to_string(),
    }
}

fn dependency_is_optional(dependency: &Dependency) -> bool {
    matches!(dependency, Dependency::Detailed(detail) if detail.optional)
}

fn dependency_resolution_options(
    dependency: &Dependency,
    parent: &ResolutionOptions,
    environment: Option<&SelectedEnvironmentContext>,
) -> ResolutionOptions {
    let mut options = ResolutionOptions {
        scope: DependencyScope::Runtime,
        environment: environment.and_then(|selected| selected.local_name.clone()),
        offline: parent.offline,
        ..ResolutionOptions::default()
    };
    if let Dependency::Detailed(detail) = dependency {
        options.features.extend(detail.features.iter().cloned());
        options.no_default_features = !detail.default_features;
    }
    options
}

fn active_optional_dependencies(manifest: &PackageManifest, options: &ResolutionOptions) -> Result<BTreeSet<String>> {
    let mut requested = options.features.clone();
    if options.all_features {
        requested.extend(manifest.features.keys().filter(|name| name.as_str() != "default").cloned());
    }
    if !options.no_default_features && manifest.features.contains_key("default") {
        requested.insert("default".to_string());
    }

    let mut active_dependencies = BTreeSet::new();
    let mut visited = BTreeSet::new();
    let mut visiting = Vec::new();
    for feature in requested {
        expand_feature(manifest, &feature, &mut visited, &mut visiting, &mut active_dependencies)?;
    }
    Ok(active_dependencies)
}

fn expand_feature(
    manifest: &PackageManifest,
    feature: &str,
    visited: &mut BTreeSet<String>,
    visiting: &mut Vec<String>,
    active_dependencies: &mut BTreeSet<String>,
) -> Result<()> {
    if visited.contains(feature) {
        return Ok(());
    }
    if visiting.iter().any(|candidate| candidate == feature) {
        let mut cycle = visiting.clone();
        cycle.push(feature.to_string());
        return Err(CompileError::without_span(format!("feature cycle detected: {}", cycle.join(" -> "))));
    }
    let members = manifest
        .features
        .get(feature)
        .ok_or_else(|| CompileError::without_span(format!("unknown package feature '{}'", feature)))?
        .clone();
    visiting.push(feature.to_string());
    for member in members {
        if let Some(alias) = member.strip_prefix("dep:") {
            let dependency = manifest.dependencies.get(alias).or_else(|| manifest.dev_dependencies.get(alias)).ok_or_else(|| {
                CompileError::without_span(format!("feature '{}' activates unknown dependency alias '{}'", feature, alias))
            })?;
            if !dependency_is_optional(dependency) {
                return Err(CompileError::without_span(format!(
                    "feature '{}' uses dep:{} but dependency '{}' is not optional",
                    feature, alias, alias
                )));
            }
            active_dependencies.insert(alias.to_string());
        } else {
            expand_feature(manifest, &member, visited, visiting, active_dependencies)?;
        }
    }
    visiting.pop();
    visited.insert(feature.to_string());
    Ok(())
}

fn validate_environment(name: &str, environment: &CkbEnvironment) -> Result<()> {
    if name.trim().is_empty() || environment.chain_id.trim().is_empty() {
        return Err(CompileError::without_span("package environment names and chain_id values must not be empty"));
    }
    let hash = environment.genesis_hash.strip_prefix("0x").unwrap_or(&environment.genesis_hash);
    if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(CompileError::without_span(format!("environment '{}' genesis_hash must contain exactly 32 bytes of hex", name)));
    }
    Ok(())
}

fn normalized_genesis_hash(value: &str) -> String {
    format!("0x{}", value.strip_prefix("0x").unwrap_or(value).to_ascii_lowercase())
}

fn same_chain_identity(left: &CkbEnvironment, right: &SelectedEnvironmentContext) -> bool {
    left.chain_id == right.chain_id && normalized_genesis_hash(&left.genesis_hash) == right.genesis_hash
}

fn root_environment_context(manifest: &PackageManifest, options: &ResolutionOptions) -> Result<Option<SelectedEnvironmentContext>> {
    let Some(name) = options.environment.as_deref() else {
        return Ok(None);
    };
    let environment = manifest.environments.get(name).ok_or_else(|| {
        CompileError::without_span(format!(
            "unknown package environment '{}'; declare [environments.{}] with chain_id and genesis_hash",
            name, name
        ))
    })?;
    validate_environment(name, environment)?;
    Ok(Some(SelectedEnvironmentContext {
        root_name: name.to_string(),
        local_name: Some(name.to_string()),
        chain_id: environment.chain_id.clone(),
        genesis_hash: normalized_genesis_hash(&environment.genesis_hash),
        policy: EnvironmentSelectionPolicy::Root,
    }))
}

fn dependency_environment_directive(dependency: &Dependency) -> (Option<&str>, bool) {
    match dependency {
        Dependency::Simple(_) => (None, false),
        Dependency::Detailed(detail) => (detail.use_environment.as_deref(), detail.environment_independent),
    }
}

fn dependency_environment_context(
    alias: &str,
    dependency: &Dependency,
    manifest: &PackageManifest,
    parent: Option<&SelectedEnvironmentContext>,
) -> Result<Option<SelectedEnvironmentContext>> {
    let (explicit_name, environment_independent) = dependency_environment_directive(dependency);
    if explicit_name.is_some() && environment_independent {
        return Err(CompileError::without_span(format!(
            "dependency '{}' cannot combine use_environment with environment_independent",
            alias
        )));
    }

    let Some(parent) = parent else {
        if let Some(name) = explicit_name {
            return Err(CompileError::without_span(format!(
                "dependency '{}' selects dependency environment '{}' without a root --environment chain identity",
                alias, name
            )));
        }
        if !environment_independent && !manifest.dependency_overrides.is_empty() {
            return Err(CompileError::without_span(format!(
                "dependency '{}' declares environment-specific dependency overrides but the edge has no selected chain identity; select a root --environment or set environment_independent = true",
                alias
            )));
        }
        return Ok(None);
    };

    let selected = if environment_independent {
        return Ok(Some(SelectedEnvironmentContext {
            root_name: parent.root_name.clone(),
            local_name: None,
            chain_id: parent.chain_id.clone(),
            genesis_hash: parent.genesis_hash.clone(),
            policy: EnvironmentSelectionPolicy::EnvironmentIndependent,
        }));
    } else if let Some(name) = explicit_name {
        let environment = manifest.environments.get(name).ok_or_else(|| {
            CompileError::without_span(format!("dependency '{}' maps to unknown dependency-local environment '{}'", alias, name))
        })?;
        if !same_chain_identity(environment, parent) {
            return Err(CompileError::without_span(format!(
                "dependency '{}' environment '{}' has chain identity '{}:{}' but the root selected '{}:{}'",
                alias,
                name,
                environment.chain_id,
                normalized_genesis_hash(&environment.genesis_hash),
                parent.chain_id,
                parent.genesis_hash
            )));
        }
        (name.to_string(), EnvironmentSelectionPolicy::ExplicitLocalName)
    } else {
        let matches = manifest
            .environments
            .iter()
            .filter(|(_, environment)| same_chain_identity(environment, parent))
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [name] => (name.clone(), EnvironmentSelectionPolicy::InheritByChainIdentity),
            [] if manifest.dependency_overrides.is_empty() => {
                return Ok(Some(SelectedEnvironmentContext {
                    root_name: parent.root_name.clone(),
                    local_name: None,
                    chain_id: parent.chain_id.clone(),
                    genesis_hash: parent.genesis_hash.clone(),
                    policy: EnvironmentSelectionPolicy::EnvironmentIndependent,
                }));
            }
            [] => {
                return Err(CompileError::without_span(format!(
                    "dependency '{}' has environment-specific overrides but no environment matches root chain identity '{}:{}'; set use_environment to an exact matching local environment or declare environment_independent = true",
                    alias, parent.chain_id, parent.genesis_hash
                )));
            }
            names => {
                return Err(CompileError::without_span(format!(
                    "dependency '{}' has multiple environments matching root chain identity '{}:{}': {}; set use_environment explicitly",
                    alias,
                    parent.chain_id,
                    parent.genesis_hash,
                    names.join(", ")
                )));
            }
        }
    };

    Ok(Some(SelectedEnvironmentContext {
        root_name: parent.root_name.clone(),
        local_name: Some(selected.0),
        chain_id: parent.chain_id.clone(),
        genesis_hash: parent.genesis_hash.clone(),
        policy: selected.1,
    }))
}

impl PackageManager {
    pub fn new(root: impl AsRef<Path>) -> Self {
        let root = root.as_ref().to_path_buf();

        Self { root, resolved: BTreeMap::new(), root_dependencies: BTreeMap::new(), selected_coordinates: BTreeMap::new() }
    }

    pub fn read_manifest(&self) -> Result<PackageManifest> {
        let manifest_path = self.root.join("Cell.toml");

        if !manifest_path.exists() {
            return Err(CompileError::without_span("Cell.toml not found. Run 'cellc init' to create a new package."));
        }

        let content = std::fs::read_to_string(&manifest_path)?;
        let manifest: PackageManifest = toml::from_str(&content)?;
        validate_declarations(&manifest.artifacts)?;
        validate_package_compiler_requirement(&manifest.package)?;
        Ok(manifest)
    }

    pub fn write_manifest(&self, manifest: &PackageManifest) -> Result<()> {
        validate_declarations(&manifest.artifacts)?;
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
                edition: CURRENT_EDITION,
                namespace: None,
                authors: vec![],
                description: String::new(),
                license: String::new(),
                repository: String::new(),
                homepage: String::new(),
                documentation: String::new(),
                keywords: vec![],
                categories: vec![],
                cellscript_version: format!(">={}", crate::VERSION),
                entry: entry.to_string(),
                source_roots: vec![],
                include: vec![],
                exclude: vec![],
            },
            workspace: None,
            artifacts: Vec::new(),
            dependencies: HashMap::new(),
            dev_dependencies: HashMap::new(),
            features: BTreeMap::new(),
            environments: BTreeMap::new(),
            dependency_overrides: BTreeMap::new(),
            resolvers: BTreeMap::new(),
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
        self.resolve_dependencies_with_options(&ResolutionOptions::default())
    }

    pub fn resolve_dependencies_with_options(&mut self, options: &ResolutionOptions) -> Result<()> {
        let manifest = self.read_manifest()?;
        self.validate_manifest_package_contract(&manifest)?;
        let root_environment = root_environment_context(&manifest, options)?;
        self.resolved.clear();
        self.root_dependencies.clear();
        self.selected_coordinates.clear();

        let result = (|| {
            let dependencies = self.selected_dependencies(&manifest, options, true)?;
            let mut compiler_errors = Vec::new();
            for (alias, dep) in dependencies {
                let node_id = self.resolve_dependency_from_root(
                    &alias,
                    &dep,
                    &manifest.package.name,
                    manifest.package.namespace.as_deref(),
                    &self.root.clone(),
                    options,
                    root_environment.as_ref(),
                    &mut Vec::new(),
                    &mut Vec::new(),
                    &mut compiler_errors,
                )?;
                if let Some(node_id) = node_id {
                    self.root_dependencies.insert(alias, node_id);
                }
            }
            if !compiler_errors.is_empty() {
                return Err(aggregate_compiler_incompatibilities(compiler_errors));
            }
            Ok(())
        })();
        if result.is_err() {
            self.resolved.clear();
            self.root_dependencies.clear();
            self.selected_coordinates.clear();
        }
        result
    }

    pub fn resolve_locked_dependencies(&mut self, options: &ResolutionOptions) -> Result<()> {
        self.resolved.clear();
        self.root_dependencies.clear();
        self.selected_coordinates.clear();
        let result = self.resolve_locked_dependencies_inner(options);
        if result.is_err() {
            self.resolved.clear();
            self.root_dependencies.clear();
            self.selected_coordinates.clear();
        }
        result
    }

    fn resolve_locked_dependencies_inner(&mut self, options: &ResolutionOptions) -> Result<()> {
        let manifest = self.read_manifest()?;
        self.validate_manifest_package_contract(&manifest)?;
        let root_environment = root_environment_context(&manifest, options)?;
        let selected = self.selected_dependencies(&manifest, options, true)?;
        if selected.is_empty() {
            if let Some(lockfile) = Lockfile::read_from_root(&self.root)? {
                validate_locked_root_compiler_contract(&lockfile, &manifest)?;
                let actual_manifest_digest = compute_manifest_digest(&self.root)?;
                if !lockfile.root.manifest_digest.is_empty() && lockfile.root.manifest_digest != actual_manifest_digest {
                    return Err(CompileError::without_span(format!(
                        "Cell.lock manifest digest '{}' does not match Cell.toml '{}'; run 'cellc lock' or 'cellc update' explicitly",
                        lockfile.root.manifest_digest, actual_manifest_digest
                    )));
                }
            }
            return Ok(());
        }

        let lockfile = Lockfile::read_from_root(&self.root)?.ok_or_else(|| {
            CompileError::without_span(
                "Cell.toml declares dependencies but Cell.lock is missing; run 'cellc lock' or 'cellc update' explicitly",
            )
        })?;
        validate_locked_root_compiler_contract(&lockfile, &manifest)?;
        let manifest_bytes = std::fs::read(self.root.join("Cell.toml"))?;
        let actual_manifest_digest = manifest_digest(&manifest_bytes);
        if lockfile.root.manifest_digest != actual_manifest_digest {
            return Err(CompileError::without_span(format!(
                "Cell.lock manifest digest '{}' does not match Cell.toml '{}'; run 'cellc lock' or 'cellc update' explicitly",
                lockfile.root.manifest_digest, actual_manifest_digest
            )));
        }

        let (runtime_edges, dev_edges) = if let Some(environment_name) = options.environment.as_deref() {
            let locked_environment = lockfile.environments.get(environment_name).ok_or_else(|| {
                CompileError::without_span(format!(
                    "environment '{}' is not pinned in Cell.lock; run 'cellc lock --environment {}'",
                    environment_name, environment_name
                ))
            })?;
            let manifest_environment = manifest
                .environments
                .get(environment_name)
                .ok_or_else(|| CompileError::without_span(format!("unknown package environment '{}'", environment_name)))?;
            if locked_environment.chain_id != manifest_environment.chain_id
                || normalized_genesis_hash(&locked_environment.genesis_hash)
                    != normalized_genesis_hash(&manifest_environment.genesis_hash)
            {
                return Err(CompileError::without_span(format!(
                    "environment '{}' chain identity differs between Cell.toml and Cell.lock; run 'cellc update --environment {}'",
                    environment_name, environment_name
                )));
            }
            (&locked_environment.dependencies, &locked_environment.dev_dependencies)
        } else {
            (&lockfile.root.dependencies, &lockfile.root.dev_dependencies)
        };

        for (alias, dependency) in selected {
            let edges = if options.scope == DependencyScope::Test && manifest.dev_dependencies.contains_key(&alias) {
                dev_edges
            } else {
                runtime_edges
            };
            let node_id = edges.get(&alias).ok_or_else(|| {
                CompileError::without_span(format!(
                    "dependency alias '{}' is not pinned for the selected mode/environment; run 'cellc lock' or 'cellc update' explicitly",
                    alias
                ))
            })?;
            let locked = lockfile
                .dependencies
                .get(node_id)
                .ok_or_else(|| CompileError::without_span(format!("Cell.lock edge '{}' targets missing node '{}'", alias, node_id)))?;
            let issues = lock_dependency_consistency_issues(
                &alias,
                &dependency,
                locked,
                manifest.package.namespace.as_deref(),
                Some((&self.root, &self.root)),
            );
            if !issues.is_empty() {
                return Err(CompileError::without_span(format!(
                    "Cell.lock dependency '{}' is inconsistent with Cell.toml: {}; run 'cellc update' explicitly",
                    alias,
                    issues.join("; ")
                )));
            }
            self.materialize_locked_node(
                node_id,
                &lockfile,
                options,
                root_environment.as_ref(),
                &alias,
                &dependency,
                &mut Vec::new(),
            )?;
            self.root_dependencies.insert(alias, node_id.clone());
        }

        Ok(())
    }

    fn materialize_locked_node(
        &mut self,
        node_id: &str,
        lockfile: &Lockfile,
        parent_options: &ResolutionOptions,
        parent_environment: Option<&SelectedEnvironmentContext>,
        edge_alias: &str,
        edge_dependency: &Dependency,
        stack: &mut Vec<String>,
    ) -> Result<()> {
        if stack.iter().any(|candidate| candidate == node_id) {
            let mut cycle = stack.clone();
            cycle.push(node_id.to_string());
            return Err(CompileError::without_span(format!("Cell.lock dependency cycle: {}", cycle.join(" -> "))));
        }
        let locked = lockfile
            .dependencies
            .get(node_id)
            .ok_or_else(|| CompileError::without_span(format!("Cell.lock is missing dependency node '{}'", node_id)))?;
        let package_path = self.locked_source_path(locked, parent_options.offline)?;
        let manifest_path = package_path.join("Cell.toml");
        let bytes = std::fs::read(&manifest_path).map_err(|error| {
            CompileError::without_span(format!("failed to read locked dependency manifest '{}': {}", manifest_path.display(), error))
        })?;
        let digest = manifest_digest(&bytes);
        if digest != locked.manifest_digest {
            return Err(CompileError::without_span(format!(
                "locked dependency '{}' manifest digest mismatch: expected '{}', got '{}'",
                node_id, locked.manifest_digest, digest
            )));
        }
        let manifest_source = std::str::from_utf8(&bytes).map_err(|error| {
            CompileError::without_span(format!("locked dependency manifest '{}' is not UTF-8: {}", manifest_path.display(), error))
        })?;
        let manifest: PackageManifest = toml::from_str(manifest_source).map_err(|error| {
            CompileError::without_span(format!("failed to parse locked dependency manifest '{}': {}", manifest_path.display(), error))
        })?;
        self.validate_manifest_package_contract(&manifest).map_err(|error| {
            let parent_package = stack
                .last()
                .and_then(|parent| lockfile.dependencies.get(parent))
                .map(|parent| parent.name.as_str())
                .unwrap_or(lockfile.package.name.as_str());
            compiler_error_with_incoming_edge(error, parent_package, edge_alias, &locked.name)
        })?;
        if locked.compiler_requirement != manifest.package.cellscript_version {
            return Err(CompileError::without_span(format!(
                "locked dependency '{}' compiler requirement '{}' does not match Cell.toml '{}'; run 'cellc update' explicitly",
                node_id, locked.compiler_requirement, manifest.package.cellscript_version
            ))
            .with_code("E2600")
            .with_details(serde_json::json!({
                "package": manifest.package.name,
                "package_version": manifest.package.version,
                "locked_compiler_requirement": locked.compiler_requirement,
                "compiler_requirement": manifest.package.cellscript_version,
                "active_compiler_version": crate::VERSION,
                "incoming_edge": {
                    "from_package": stack
                        .last()
                        .and_then(|parent| lockfile.dependencies.get(parent))
                        .map(|parent| parent.name.as_str())
                        .unwrap_or(lockfile.package.name.as_str()),
                    "alias": edge_alias,
                    "to_package": manifest.package.name,
                },
                "phase": "locked-materialization",
            })));
        }
        if manifest.package.name != locked.name || manifest.package.version != locked.version {
            return Err(CompileError::without_span(format!(
                "locked dependency '{}' manifest identity is '{}@{}', expected '{}@{}'",
                node_id, manifest.package.name, manifest.package.version, locked.name, locked.version
            )));
        }
        let source_hash = registry::compute_source_hash(&package_path)?;
        if locked.source_hash.as_deref() != Some(source_hash.as_str()) {
            return Err(CompileError::without_span(format!(
                "locked dependency '{}' source hash mismatch: expected '{}', got '{}'",
                node_id,
                locked.source_hash.as_deref().unwrap_or("<missing>"),
                source_hash
            )));
        }

        let node_environment = dependency_environment_context(edge_alias, edge_dependency, &manifest, parent_environment)?;
        let node_options = dependency_resolution_options(edge_dependency, parent_options, node_environment.as_ref());
        let locked_package = ResolvedPackage {
            node_id: String::new(),
            name: locked.name.clone(),
            version: locked.version.clone(),
            path: package_path.clone(),
            source: locked_source_to_package_source(&locked.source),
            dependencies: BTreeMap::new(),
            namespace: locked.namespace.clone(),
            source_hash: Some(source_hash.clone()),
            manifest_digest: digest.clone(),
            compiler_requirement: manifest.package.cellscript_version.clone(),
        };
        let expected_node_id = package_node_id(&locked_package, &node_options, node_environment.as_ref());
        if node_id != expected_node_id {
            return Err(CompileError::without_span(format!(
                "Cell.lock dependency edge '{}' records node '{}' but its chain-identity-safe environment selection requires '{}'; run 'cellc update' explicitly",
                edge_alias, node_id, expected_node_id
            )));
        }
        let parent_package = stack
            .last()
            .and_then(|parent| lockfile.dependencies.get(parent))
            .map(|parent| parent.name.as_str())
            .unwrap_or(lockfile.package.name.as_str());
        let selected_node = self.register_package_instance(
            &locked_package,
            node_id,
            &node_options,
            node_environment.as_ref(),
            parent_package,
            edge_alias,
            edge_dependency,
            true,
        )?;
        if selected_node != node_id {
            return Err(CompileError::without_span(format!(
                "Cell.lock edge '{}' selected non-canonical duplicate package node '{}' instead of '{}'",
                edge_alias, node_id, selected_node
            ))
            .with_code("E2601"));
        }
        if self.resolved.contains_key(node_id) {
            return Ok(());
        }

        let selected_dependencies = self.selected_dependencies(&manifest, &node_options, false)?;
        let mut selected_edges = BTreeMap::new();
        stack.push(node_id.to_string());
        for (alias, dependency) in selected_dependencies {
            let target = locked.dependencies.get(&alias).ok_or_else(|| {
                CompileError::without_span(format!(
                    "locked dependency node '{}' has no edge for selected dependency alias '{}'",
                    node_id, alias
                ))
            })?;
            let target_lock = lockfile.dependencies.get(target).ok_or_else(|| {
                CompileError::without_span(format!(
                    "locked dependency node '{}' edge '{}' targets missing node '{}'",
                    node_id, alias, target
                ))
            })?;
            let issues = lock_dependency_consistency_issues(
                &alias,
                &dependency,
                target_lock,
                manifest.package.namespace.as_deref(),
                Some((&package_path, &self.root)),
            );
            if !issues.is_empty() {
                return Err(CompileError::without_span(format!(
                    "locked dependency node '{}' edge '{}' is inconsistent with its manifest: {}",
                    node_id,
                    alias,
                    issues.join("; ")
                )));
            }
            self.materialize_locked_node(target, lockfile, &node_options, node_environment.as_ref(), &alias, &dependency, stack)?;
            selected_edges.insert(alias, target.clone());
        }
        stack.pop();

        self.resolved.insert(
            node_id.to_string(),
            ResolvedPackage {
                node_id: node_id.to_string(),
                name: locked.name.clone(),
                version: locked.version.clone(),
                path: package_path,
                source: locked_source_to_package_source(&locked.source),
                dependencies: selected_edges,
                namespace: locked.namespace.clone(),
                source_hash: Some(source_hash),
                manifest_digest: digest,
                compiler_requirement: manifest.package.cellscript_version.clone(),
            },
        );
        Ok(())
    }

    fn locked_source_path(&self, locked: &LockedDependency, offline: bool) -> Result<PathBuf> {
        match &locked.source {
            LockedSource::Path { path } => {
                let path = self.root.join(path);
                if !path.is_dir() {
                    return Err(CompileError::without_span(format!("locked path dependency '{}' does not exist", path.display())));
                }
                Ok(path)
            }
            LockedSource::Git { url, revision } => {
                let path = self.git_cache_dir().join(format!("{}-git-{}", locked.name, revision));
                if !path.exists() {
                    if offline {
                        return Err(CompileError::without_span(format!(
                            "offline mode cannot materialize missing git cache '{}' for {}",
                            path.display(),
                            locked.name
                        )));
                    }
                    std::fs::create_dir_all(self.git_cache_dir())?;
                    Self::git_materialize_locked(url, &path, revision).map_err(CompileError::without_span)?;
                }
                let actual = Self::git_revision(&path).map_err(CompileError::without_span)?;
                if actual != *revision {
                    return Err(CompileError::without_span(format!(
                        "locked git cache '{}' has revision '{}', expected '{}'",
                        path.display(),
                        actual,
                        revision
                    )));
                }
                Ok(path)
            }
            LockedSource::Registry { url, revision, namespace, version, .. } => {
                let suffix = revision.trim_start_matches("sha256:");
                let path = self.git_cache_dir().join(format!("{}-snapshot-{}", locked.name, suffix));
                if !path.exists() {
                    if offline {
                        return Err(CompileError::without_span(format!(
                            "offline mode cannot materialize missing Registry cache '{}' for {}",
                            path.display(),
                            locked.name
                        )));
                    }
                    registry::materialize_locked_public_source_snapshot(
                        url,
                        revision,
                        &self.git_cache_dir(),
                        namespace,
                        &locked.name,
                        version,
                        locked.source_hash.as_deref().unwrap_or_default(),
                    )?;
                }
                Ok(path)
            }
        }
    }

    fn validate_manifest_package_contract(&self, manifest: &PackageManifest) -> Result<()> {
        validate_package_compiler_requirement(&manifest.package)?;
        self.validate_manifest_package_structure(manifest)
    }

    fn validate_manifest_package_structure(&self, manifest: &PackageManifest) -> Result<()> {
        validate_declarations(&manifest.artifacts)?;
        semver::Version::parse(&manifest.package.version).map_err(|error| {
            CompileError::without_span(format!(
                "package '{}' has invalid semantic version '{}': {error}",
                manifest.package.name, manifest.package.version
            ))
        })?;
        for (name, environment) in &manifest.environments {
            validate_environment(name, environment)?;
        }
        for environment in manifest.dependency_overrides.keys() {
            if !manifest.environments.contains_key(environment) {
                return Err(CompileError::without_span(format!(
                    "dependency override environment '{}' has no matching [environments.{}] declaration",
                    environment, environment
                )));
            }
        }
        for (name, resolver) in &manifest.resolvers {
            if name.trim().is_empty() {
                return Err(CompileError::without_span("resolver names must not be empty"));
            }
            let command = Path::new(&resolver.command);
            if !command.is_absolute() {
                return Err(CompileError::without_span(format!("resolver '{}' command must be an absolute executable path", name)));
            }
            let digest = resolver.sha256.strip_prefix("sha256:").unwrap_or(&resolver.sha256);
            if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(CompileError::without_span(format!("resolver '{}' sha256 must contain exactly 32 bytes of hex", name)));
            }
        }
        let declared_dependencies = manifest
            .dependencies
            .iter()
            .chain(manifest.dev_dependencies.iter())
            .chain(manifest.dependency_overrides.values().flat_map(|dependencies| dependencies.iter()));
        for (alias, dependency) in declared_dependencies {
            if let Dependency::Detailed(detail) = dependency {
                if detail.use_environment.as_deref().is_some_and(|name| name.trim().is_empty()) {
                    return Err(CompileError::without_span(format!("dependency '{}' use_environment must not be empty", alias)));
                }
                if detail.use_environment.is_some() && detail.environment_independent {
                    return Err(CompileError::without_span(format!(
                        "dependency '{}' cannot combine use_environment with environment_independent",
                        alias
                    )));
                }
                if let Some(resolver) = detail.resolver.as_deref() {
                    if detail.path.is_some() || detail.git.is_some() {
                        return Err(CompileError::without_span(format!(
                            "dependency '{}' cannot combine resolver with path or git",
                            alias
                        )));
                    }
                    if !manifest.resolvers.contains_key(resolver) {
                        return Err(CompileError::without_span(format!(
                            "dependency '{}' selects undeclared resolver '{}'",
                            alias, resolver
                        )));
                    }
                }
            }
        }
        if !manifest.build.dependencies.is_empty() {
            return Err(CompileError::without_span(
                "[build.dependencies] is reserved until isolated build-script execution is implemented; use [dependencies] for compile-time imports",
            ));
        }
        Ok(())
    }

    fn selected_dependencies(
        &self,
        manifest: &PackageManifest,
        options: &ResolutionOptions,
        root: bool,
    ) -> Result<BTreeMap<String, Dependency>> {
        let mut dependencies: BTreeMap<String, Dependency> =
            manifest.dependencies.iter().map(|(name, dep)| (name.clone(), dep.clone())).collect();
        if options.scope == DependencyScope::Test && root {
            for (name, dep) in &manifest.dev_dependencies {
                if dependencies.insert(name.clone(), dep.clone()).is_some() {
                    return Err(CompileError::without_span(format!(
                        "dependency alias '{}' is declared in both [dependencies] and [dev_dependencies]",
                        name
                    )));
                }
            }
        }

        if let Some(environment) = options.environment.as_deref() {
            if root && !manifest.environments.contains_key(environment) {
                return Err(CompileError::without_span(format!(
                    "unknown package environment '{}'; declare [environments.{}] with chain_id and genesis_hash",
                    environment, environment
                )));
            }
            if let Some(overrides) = manifest.dependency_overrides.get(environment) {
                for (alias, dependency) in overrides {
                    if !dependencies.contains_key(alias) {
                        return Err(CompileError::without_span(format!(
                            "environment '{}' overrides unknown dependency alias '{}'",
                            environment, alias
                        )));
                    }
                    dependencies.insert(alias.clone(), dependency.clone());
                }
            }
        } else if root && !manifest.dependency_overrides.is_empty() {
            return Err(CompileError::without_span(
                "Cell.toml declares environment-specific dependency overrides; select one explicitly with --environment",
            ));
        }

        let active_optional = active_optional_dependencies(manifest, options)?;
        dependencies.retain(|alias, dependency| !dependency_is_optional(dependency) || active_optional.contains(alias));
        Ok(dependencies)
    }

    /// Extract the version-requirement string carried by a dependency, if any.
    ///
    /// Path and git dependencies without a meaningful version return `None`,
    /// which the unified resolver treats as "no constraint to check". Only
    /// registry dependencies (Simple or Detailed with a version) contribute a
    /// constraint that must be reconciled across the graph.
    fn version_requirement_of(&self, dep: &Dependency) -> Option<String> {
        match dep {
            Dependency::Simple(version) => Some(version.clone()),
            Dependency::Detailed(detailed) => {
                // Path/git sources and wildcard versions carry no constraint
                // for the unified resolver to reconcile across the graph.
                if detailed.path.is_some() || detailed.git.is_some() || detailed.version.is_empty() || detailed.version == "*" {
                    None
                } else {
                    Some(detailed.version.clone())
                }
            }
        }
    }

    fn register_package_instance(
        &mut self,
        package: &ResolvedPackage,
        node_id: &str,
        options: &ResolutionOptions,
        environment: Option<&SelectedEnvironmentContext>,
        parent_package: &str,
        alias: &str,
        dependency: &Dependency,
        locked: bool,
    ) -> Result<String> {
        let coordinate = PackageCoordinate::from_package(package);
        let features = FeatureSelection::from_options(options);
        let environment = environment.map(environment_node_identity);
        let source_authority = package_source_authority(package);
        let source_identity = package_source_identity(package);
        let reusable_requirement =
            self.version_requirement_of(dependency).and_then(|requirement| version::parse_version_req(&requirement).ok());
        let current = IncomingPackageRequest {
            parent_package: parent_package.to_string(),
            alias: alias.to_string(),
            version_requirement: dependency_requirement_for_diagnostic(dependency),
            candidate_version: package.version.clone(),
            candidate_source: source_identity.clone(),
            features: features.clone(),
            environment: environment.clone(),
        };
        let Some(selected) = self.selected_coordinates.get_mut(&coordinate) else {
            self.selected_coordinates.insert(
                coordinate,
                SelectedPackageInstance {
                    node_id: node_id.to_string(),
                    version: package.version.clone(),
                    manifest_digest: package.manifest_digest.clone(),
                    compiler_requirement: package.compiler_requirement.clone(),
                    source_authority,
                    source_identity,
                    source_is_registry: matches!(package.source, PackageSource::Registry { .. }),
                    features,
                    environment,
                    incoming: vec![current],
                },
            );
            return Ok(node_id.to_string());
        };

        let conflict_kind = if selected.environment != environment {
            Some("environment")
        } else if selected.features != features {
            Some("feature")
        } else if selected.version == package.version {
            (selected.source_identity != source_identity
                || selected.manifest_digest != package.manifest_digest
                || selected.compiler_requirement != package.compiler_requirement)
                .then_some("source")
        } else if locked || !selected.source_is_registry || !matches!(package.source, PackageSource::Registry { .. }) {
            Some(if selected.source_authority == source_authority { "version" } else { "source" })
        } else if selected.source_authority != source_authority {
            Some("source")
        } else if reusable_requirement.is_some_and(|requirement| !version::satisfies(&selected.version, &requirement)) {
            Some("version")
        } else {
            None
        };

        if let Some(conflict_kind) = conflict_kind {
            let mut incoming = selected.incoming.clone();
            incoming.push(current);
            let selected_json = serde_json::json!({
                "node_id": selected.node_id,
                "version": selected.version,
                "source": selected.source_identity,
                "features": selected.features.labels(),
                "environment": selected.environment,
            });
            return Err(CompileError::without_span(format!(
                "package instance conflict for '{}': selected {} cannot satisfy incoming dependency '{} -> {}' ({conflict_kind}); align every incoming dependency declaration on one explicit package instance",
                coordinate.display(),
                selected.node_id,
                parent_package,
                alias,
            ))
            .with_code("E2601")
            .with_details(serde_json::json!({
                "coordinate": {
                    "namespace": coordinate.namespace,
                    "name": coordinate.name,
                },
                "conflict_kind": conflict_kind,
                "selected": selected_json,
                "incoming_edges": incoming.iter().map(incoming_package_request_json).collect::<Vec<_>>(),
                "locked": locked,
                "phase": if locked { "locked-package-unification" } else { "package-unification" },
            })));
        }

        selected.incoming.push(current);
        Ok(selected.node_id.clone())
    }

    fn resolve_dependency_from_root(
        &mut self,
        alias: &str,
        dep: &Dependency,
        parent_package: &str,
        parent_namespace: Option<&str>,
        base_root: &Path,
        parent_options: &ResolutionOptions,
        parent_environment: Option<&SelectedEnvironmentContext>,
        stack_ids: &mut Vec<String>,
        stack_labels: &mut Vec<String>,
        compiler_errors: &mut Vec<CompileError>,
    ) -> Result<Option<String>> {
        let package_name = dependency_package_name(alias, dep);
        let resolution: Result<(ResolvedPackage, PackageManifest)> = (|| match dep {
            Dependency::Simple(version) => self.resolve_from_registry_with_manifest(
                &package_name,
                version,
                None,
                parent_namespace,
                registry::RegistryResolutionPolicy::default(),
            ),
            Dependency::Detailed(detailed) => {
                if detailed.resolver.is_some() {
                    let normalized = self.resolve_external_dependency(
                        alias,
                        &package_name,
                        detailed,
                        base_root,
                        parent_options,
                        parent_environment,
                    )?;
                    let resolved = if let Some(git) = &normalized.git {
                        self.resolve_from_git_with_manifest(&package_name, git, &normalized)?
                    } else {
                        self.resolve_from_registry_with_manifest(
                            &package_name,
                            &normalized.version,
                            normalized.namespace.as_deref(),
                            parent_namespace,
                            registry::RegistryResolutionPolicy::default(),
                        )?
                    };
                    let exact = version::parse_version_req(&normalized.version)?;
                    if !version::satisfies(&resolved.0.version, &exact) {
                        return Err(CompileError::without_span(format!(
                            "external resolver for '{}' declared version inconsistent with materialized package '{}'",
                            alias, resolved.0.version
                        )));
                    }
                    Ok(resolved)
                } else if let Some(path) = &detailed.path {
                    self.resolve_from_path_at(&package_name, path, base_root)
                } else if let Some(git) = &detailed.git {
                    self.resolve_from_git_with_manifest(&package_name, git, detailed)
                } else {
                    let ns = detailed.namespace.as_deref();
                    self.resolve_from_registry_with_manifest(
                        &package_name,
                        &detailed.version,
                        ns,
                        parent_namespace,
                        registry::RegistryResolutionPolicy {
                            allow_unverified: detailed.allow_unverified,
                            allow_quarantined: detailed.allow_quarantined,
                        },
                    )
                }
            }
        })();
        let (mut resolved, manifest) = match resolution {
            Ok(resolution) => resolution,
            Err(error) if error.code.as_deref() == Some("E2600") => {
                compiler_errors.push(compiler_error_with_incoming_edge(error, parent_package, alias, &package_name));
                return Ok(None);
            }
            Err(error) => return Err(error),
        };

        if let Err(error) = validate_package_compiler_requirement(&manifest.package) {
            compiler_errors.push(compiler_error_with_incoming_edge(error, parent_package, alias, &package_name));
        }
        self.validate_manifest_package_structure(&manifest)?;
        if manifest.package.name != package_name {
            return Err(CompileError::without_span(format!(
                "dependency alias '{}' expects package '{}' but '{}' declares package name '{}'",
                alias,
                package_name,
                resolved.path.display(),
                manifest.package.name
            )));
        }
        let child_environment = dependency_environment_context(alias, dep, &manifest, parent_environment)?;
        let child_options = dependency_resolution_options(dep, parent_options, child_environment.as_ref());
        let candidate_node_id = package_node_id(&resolved, &child_options, child_environment.as_ref());
        if let Some(requirement) = self.version_requirement_of(dep) {
            let requirement = version::parse_version_req(&requirement)?;
            if !version::satisfies(&resolved.version, &requirement) {
                return Err(CompileError::without_span(format!(
                    "dependency alias '{}' resolved package '{}' to '{}', which does not satisfy its requirement",
                    alias, package_name, resolved.version
                )));
            }
        }
        let node_id = self.register_package_instance(
            &resolved,
            &candidate_node_id,
            &child_options,
            child_environment.as_ref(),
            parent_package,
            alias,
            dep,
            false,
        )?;
        if let Some(position) = stack_ids.iter().position(|item| item == &node_id) {
            let mut cycle = stack_labels[position..].to_vec();
            cycle.push(alias.to_string());
            return Err(CompileError::without_span(format!("Circular dependency detected: {}", cycle.join(" -> "))));
        }
        if let Some(existing) = self.resolved.get(&node_id) {
            if existing.manifest_digest != resolved.manifest_digest || existing.source_hash != resolved.source_hash {
                if node_id == candidate_node_id {
                    return Err(CompileError::without_span(format!(
                        "dependency node '{}' resolved with conflicting manifest or source identity",
                        node_id
                    )));
                }
            }
            return Ok(Some(node_id));
        }

        stack_ids.push(node_id.clone());
        stack_labels.push(alias.to_string());
        let child_dependencies = self.selected_dependencies(&manifest, &child_options, false)?;
        let mut child_edges = BTreeMap::new();
        for (child_alias, child_dep) in child_dependencies {
            let child_id = self.resolve_dependency_from_root(
                &child_alias,
                &child_dep,
                &manifest.package.name,
                manifest.package.namespace.as_deref(),
                &resolved.path,
                &child_options,
                child_environment.as_ref(),
                stack_ids,
                stack_labels,
                compiler_errors,
            )?;
            if let Some(child_id) = child_id {
                child_edges.insert(child_alias, child_id);
            }
        }
        stack_ids.pop();
        stack_labels.pop();

        resolved.node_id = node_id.clone();
        resolved.dependencies = child_edges;
        self.resolved.insert(node_id.clone(), resolved);
        Ok(Some(node_id))
    }

    fn resolve_external_dependency(
        &self,
        alias: &str,
        package_name: &str,
        dependency: &DetailedDependency,
        owner_root: &Path,
        options: &ResolutionOptions,
        environment_context: Option<&SelectedEnvironmentContext>,
    ) -> Result<DetailedDependency> {
        if options.offline {
            return Err(CompileError::without_span(format!(
                "offline mode cannot invoke external resolver for dependency '{}'",
                alias
            )));
        }
        let resolver_name = dependency
            .resolver
            .as_deref()
            .ok_or_else(|| CompileError::without_span(format!("dependency '{}' has no external resolver name", alias)))?;
        let owner_manifest_path = owner_root.join("Cell.toml");
        let owner_manifest: PackageManifest = toml::from_str(&std::fs::read_to_string(&owner_manifest_path).map_err(|error| {
            CompileError::without_span(format!(
                "failed to read resolver owner manifest '{}': {}",
                owner_manifest_path.display(),
                error
            ))
        })?)?;
        let resolver = owner_manifest.resolvers.get(resolver_name).ok_or_else(|| {
            CompileError::without_span(format!("dependency '{}' selects undeclared resolver '{}'", alias, resolver_name))
        })?;
        if resolver.args.len() > 64 || resolver.args.iter().any(|argument| argument.len() > 4096) {
            return Err(CompileError::without_span(format!("resolver '{}' exceeds the bounded argument contract", resolver_name)));
        }
        let command_path = Path::new(&resolver.command);
        if !command_path.is_absolute() || !command_path.is_file() {
            return Err(CompileError::without_span(format!(
                "resolver '{}' command must be an existing absolute executable path",
                resolver_name
            )));
        }
        let expected_digest = resolver.sha256.strip_prefix("sha256:").unwrap_or(&resolver.sha256).to_ascii_lowercase();
        let actual_digest = sha256_file(command_path)?;
        if actual_digest != expected_digest {
            return Err(CompileError::without_span(format!(
                "resolver '{}' executable digest mismatch: expected sha256:{}, got sha256:{}",
                resolver_name, expected_digest, actual_digest
            )));
        }

        let environment = environment_context.map(|selected| ExternalResolverEnvironment {
            root_name: &selected.root_name,
            local_name: selected.local_name.as_deref(),
            chain_id: &selected.chain_id,
            genesis_hash: &selected.genesis_hash,
        });
        let request = ExternalResolverRequest {
            schema: EXTERNAL_RESOLVER_REQUEST_SCHEMA,
            alias,
            package: package_name,
            version_requirement: &dependency.version,
            environment,
        };
        let request = serde_json::to_vec(&request)?;
        let temp_root = self.root.join(".cell/resolver-tmp");
        std::fs::create_dir_all(&temp_root)?;
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        let stem = format!("{}-{}-{nonce}", std::process::id(), sanitize_node_component(alias));
        let stdout_path = temp_root.join(format!("{stem}.stdout"));
        let stderr_path = temp_root.join(format!("{stem}.stderr"));
        let stdout_file = std::fs::OpenOptions::new().write(true).create_new(true).open(&stdout_path)?;
        let stderr_file = std::fs::OpenOptions::new().write(true).create_new(true).open(&stderr_path)?;
        let mut child = std::process::Command::new(command_path)
            .args(&resolver.args)
            .current_dir(owner_root)
            .env_clear()
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::from(stdout_file))
            .stderr(std::process::Stdio::from(stderr_file))
            .spawn()
            .map_err(|error| CompileError::without_span(format!("failed to start resolver '{}': {}", resolver_name, error)))?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(&request)?;
            stdin.write_all(b"\n")?;
        }

        let started = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            let output_too_large = [&stdout_path, &stderr_path]
                .iter()
                .any(|path| std::fs::metadata(path).is_ok_and(|metadata| metadata.len() > EXTERNAL_RESOLVER_MAX_OUTPUT_BYTES));
            if output_too_large || started.elapsed() >= EXTERNAL_RESOLVER_TIMEOUT {
                let _ = child.kill();
                let _ = child.wait();
                let _ = std::fs::remove_file(&stdout_path);
                let _ = std::fs::remove_file(&stderr_path);
                let reason = if output_too_large { "output exceeded 1 MiB" } else { "timed out after 10 seconds" };
                return Err(CompileError::without_span(format!("resolver '{}' {}", resolver_name, reason)));
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let stdout = read_bounded_resolver_output(&stdout_path)?;
        let stderr = read_bounded_resolver_output(&stderr_path)?;
        let _ = std::fs::remove_file(&stdout_path);
        let _ = std::fs::remove_file(&stderr_path);
        if !status.success() {
            return Err(CompileError::without_span(format!(
                "resolver '{}' exited with {}: {}",
                resolver_name,
                status,
                String::from_utf8_lossy(&stderr).trim()
            )));
        }
        let response: ExternalResolverResponse = serde_json::from_slice(&stdout)
            .map_err(|error| CompileError::without_span(format!("resolver '{}' returned invalid JSON: {}", resolver_name, error)))?;
        if response.schema != EXTERNAL_RESOLVER_RESPONSE_SCHEMA {
            return Err(CompileError::without_span(format!(
                "resolver '{}' returned unsupported schema '{}'",
                resolver_name, response.schema
            )));
        }
        if response.dependency.package != package_name {
            return Err(CompileError::without_span(format!(
                "resolver '{}' returned package '{}', expected '{}'",
                resolver_name, response.dependency.package, package_name
            )));
        }
        semver::Version::parse(&response.dependency.version).map_err(|error| {
            CompileError::without_span(format!(
                "resolver '{}' version '{}' is not exact SemVer: {}",
                resolver_name, response.dependency.version, error
            ))
        })?;
        let requested = version::parse_version_req(&dependency.version)?;
        if !version::satisfies(&response.dependency.version, &requested) {
            return Err(CompileError::without_span(format!(
                "resolver '{}' returned version '{}' outside requested range '{}'",
                resolver_name, response.dependency.version, dependency.version
            )));
        }

        match (&response.dependency.git, &response.dependency.namespace) {
            (Some(git), None) => {
                let revision =
                    response.dependency.rev.as_deref().ok_or_else(|| {
                        CompileError::without_span(format!("resolver '{}' Git response requires rev", resolver_name))
                    })?;
                if revision.len() != 40 || !revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    return Err(CompileError::without_span(format!(
                        "resolver '{}' Git rev must be a full 40-hex commit",
                        resolver_name
                    )));
                }
                Ok(DetailedDependency {
                    version: format!("={}", response.dependency.version),
                    namespace: None,
                    package: dependency.package.clone(),
                    resolver: None,
                    git: Some(git.clone()),
                    branch: None,
                    tag: None,
                    rev: Some(revision.to_string()),
                    path: None,
                    optional: dependency.optional,
                    features: dependency.features.clone(),
                    default_features: dependency.default_features,
                    use_environment: None,
                    environment_independent: false,
                    allow_unverified: false,
                    allow_quarantined: false,
                })
            }
            (None, Some(namespace)) => {
                if response.dependency.rev.is_some() || namespace.trim().is_empty() {
                    return Err(CompileError::without_span(format!("resolver '{}' Registry response is malformed", resolver_name)));
                }
                Ok(DetailedDependency {
                    version: format!("={}", response.dependency.version),
                    namespace: Some(namespace.clone()),
                    package: dependency.package.clone(),
                    resolver: None,
                    git: None,
                    branch: None,
                    tag: None,
                    rev: None,
                    path: None,
                    optional: dependency.optional,
                    features: dependency.features.clone(),
                    default_features: dependency.default_features,
                    use_environment: None,
                    environment_independent: false,
                    allow_unverified: dependency.allow_unverified,
                    allow_quarantined: dependency.allow_quarantined,
                })
            }
            _ => Err(CompileError::without_span(format!("resolver '{}' must return exactly one of git or namespace", resolver_name))),
        }
    }

    pub fn resolve_from_registry(&self, name: &str, version: &str) -> Result<ResolvedPackage> {
        self.resolve_from_registry_with_namespace(name, version, None)
    }

    pub fn resolve_from_registry_with_namespace(&self, name: &str, version: &str, namespace: Option<&str>) -> Result<ResolvedPackage> {
        let (resolved, _) =
            self.resolve_from_registry_with_manifest(name, version, namespace, None, registry::RegistryResolutionPolicy::default())?;
        Ok(resolved)
    }

    pub fn resolve_from_registry_with_namespace_and_policy(
        &self,
        name: &str,
        version: &str,
        namespace: Option<&str>,
        policy: registry::RegistryResolutionPolicy,
    ) -> Result<ResolvedPackage> {
        let (resolved, _) = self.resolve_from_registry_with_manifest(name, version, namespace, None, policy)?;
        Ok(resolved)
    }

    fn resolve_from_registry_with_manifest(
        &self,
        name: &str,
        version: &str,
        namespace: Option<&str>,
        consuming_namespace: Option<&str>,
        policy: registry::RegistryResolutionPolicy,
    ) -> Result<(ResolvedPackage, PackageManifest)> {
        // 1. Determine namespace: explicit > consuming package namespace > error
        let resolved_namespace = namespace
            .map(str::to_string)
            .or_else(|| consuming_namespace.map(str::to_string))
            .or_else(|| {
                // Try to use consuming package's namespace
                self.read_manifest().ok().and_then(|m| m.package.namespace)
            })
            .ok_or_else(|| {
                CompileError::without_span(format!(
                    "registry dependency '{}' requires a namespace; specify namespace in dependency or set namespace in [package]",
                    name
                ))
            })?;

        // 2. Resolve accepted public-registry state (or an explicitly selected
        //    offline Git mirror) → find the source repository URL.
        let cache_dir = self.registry_cache_dir();
        let registry_resolution = registry::lookup_for_resolution(&resolved_namespace, name, &cache_dir).map_err(|e| {
            CompileError::without_span(format!(
                "failed to resolve registry dependency '{}/{}@{}': {}",
                resolved_namespace, name, version, e
            ))
        })?;
        let registry::RegistryResolution { registry_url, entry, authoritative_index, mut source_snapshots } = registry_resolution;
        let repository_url = entry.source;

        // 3. Prepare the immutable Registry snapshot cache, or clone the
        //    explicitly selected legacy Git mirror.
        let source_cache = self.git_cache_dir();
        std::fs::create_dir_all(&source_cache)
            .map_err(|e| CompileError::without_span(format!("failed to create source cache directory: {}", e)))?;
        let public_registry_authoritative = authoritative_index.is_some();
        let legacy_clone = if public_registry_authoritative {
            None
        } else {
            let cache_key = format!("{}#{}", repository_url, version);
            let cache_name = format!("{}-{:016x}", name, simple_hash(&cache_key));
            let clone_dir = source_cache.join(&cache_name);
            if clone_dir.exists() && clone_dir.join(".git").exists() {
                registry::git_update(&clone_dir).map_err(CompileError::without_span)?;
            } else {
                let _ = std::fs::remove_dir_all(&clone_dir);
                registry::git_clone(&repository_url, &clone_dir).map_err(CompileError::without_span)?;
            }
            Some(clone_dir)
        };

        // 4. Resolve versions against production-accepted status. A legacy
        //    Git override retains the historical registry.json authority.
        let reg_index = match authoritative_index {
            Some(index) => index,
            None => registry::RegistryIndex::read_from_repo(legacy_clone.as_ref().expect("legacy clone exists"))?,
        };
        reg_index.ensure_current_schema()?;
        if reg_index.name != name || reg_index.namespace != resolved_namespace {
            return Err(CompileError::without_span(format!(
                "registry.json identity mismatch for '{}/{}': found '{}/{}'",
                resolved_namespace, name, reg_index.namespace, reg_index.name
            )));
        }
        let selected_version = reg_index.find_matching_version_for_resolution(version, policy).cloned().ok_or_else(|| {
            if let Some(incompatible) = reg_index.find_matching_version_for_resolution_ignoring_compiler(version, policy) {
                return CompileError::without_span(format!(
                    "registry package '{}/{}@{}' matched version '{}' requiring CellScript compiler '{}', but active cellc is '{}'; update selected the newest compiler-compatible release only",
                    resolved_namespace,
                    name,
                    version,
                    incompatible.version,
                    incompatible.compiler_requirement,
                    crate::VERSION
                ))
                .with_code("E2600")
                .with_details(serde_json::json!({
                    "package": name,
                    "namespace": resolved_namespace,
                    "requested_version": version,
                    "matched_package_version": incompatible.version,
                    "compiler_requirement": incompatible.compiler_requirement,
                    "active_compiler_version": crate::VERSION,
                    "phase": "registry-candidate-selection",
                }));
            }
            if let Some(blocked) = reg_index.find_matching_version_allowing_yanked_pin(version) {
                return registry_resolution_blocked_error(&resolved_namespace, name, version, blocked, policy);
            }
            CompileError::without_span(format!("no matching version found for '{}/{}@{}'", resolved_namespace, name, version))
        })?;
        emit_yank_notices(&resolved_namespace, name, version, &selected_version.version, &reg_index);
        if selected_version.source_hash.is_empty() {
            return Err(CompileError::without_span(format!(
                "registry package '{}/{}@{}' has no source_hash in registry.json",
                resolved_namespace, name, selected_version.version
            )));
        }

        // 5. Public resolution materializes the content-addressed Registry
        //    snapshot. The explicit Git override retains tag/registry.json
        //    cross-checking for offline and private mirrors.
        let (package_dir, revision, source_url, tagged_version) = if public_registry_authoritative {
            let snapshot = source_snapshots.remove(&selected_version.version).ok_or_else(|| {
                CompileError::without_span(format!(
                    "public registry package '{}/{}@{}' has no immutable source snapshot",
                    resolved_namespace, name, selected_version.version
                ))
            })?;
            let source_url = snapshot.url.clone();
            let revision = snapshot.snapshot_hash.clone();
            let package_dir = registry::materialize_public_source_snapshot(
                &snapshot,
                &source_cache,
                &resolved_namespace,
                name,
                &selected_version.version,
                &selected_version.source_hash,
            )?;
            (package_dir, revision, source_url, selected_version.clone())
        } else {
            let clone_dir = legacy_clone.expect("legacy clone exists");
            registry::git_checkout(&clone_dir, &selected_version.tag).map_err(CompileError::without_span)?;
            let revision = registry::git_revision(&clone_dir).unwrap_or_else(|_| "unknown".to_string());
            let tagged_index = registry::RegistryIndex::read_from_repo(&clone_dir)?;
            if tagged_index.schema_version != registry::RegistryIndex::CURRENT_SCHEMA_VERSION {
                return Err(CompileError::without_span(format!(
                    "registry package '{}/{}@{}' uses unsupported registry.json schema_version {}; expected {}",
                    resolved_namespace,
                    name,
                    selected_version.version,
                    tagged_index.schema_version,
                    registry::RegistryIndex::CURRENT_SCHEMA_VERSION
                )));
            }
            if tagged_index.name != name || tagged_index.namespace != resolved_namespace {
                return Err(CompileError::without_span(format!(
                    "registry.json identity mismatch for checked-out '{}/{}@{}': found '{}/{}'",
                    resolved_namespace, name, selected_version.version, tagged_index.namespace, tagged_index.name
                )));
            }
            let tagged_version =
                tagged_index.versions.iter().find(|candidate| candidate.version == selected_version.version).cloned().ok_or_else(
                    || {
                        CompileError::without_span(format!(
                            "registry package '{}/{}@{}' tag '{}' does not contain a matching registry.json version entry",
                            resolved_namespace, name, selected_version.version, selected_version.tag
                        ))
                    },
                )?;
            if tagged_version.source_hash != selected_version.source_hash
                || tagged_version.tag != selected_version.tag
                || tagged_version.cellscript_version != selected_version.cellscript_version
                || tagged_version.compiler_requirement != selected_version.compiler_requirement
                || tagged_version.edition != selected_version.edition
                || tagged_version.compatibility_profile_hash != selected_version.compatibility_profile_hash
            {
                return Err(CompileError::without_span(format!(
                    "registry identity mismatch for '{}/{}@{}' between the selected index and checked-out tag",
                    resolved_namespace, name, tagged_version.version
                )));
            }
            if tagged_version
                .resolver_block_reason(policy, matches!(crate::package::version::parse_version_req(version), Ok(VersionReq::Exact(_))))
                .is_some()
            {
                return Err(registry_resolution_blocked_error(&resolved_namespace, name, version, &tagged_version, policy));
            }
            (clone_dir, revision, repository_url.clone(), tagged_version)
        };
        let computed_source_hash = registry::compute_source_hash(&package_dir)?;
        if computed_source_hash != tagged_version.source_hash {
            return Err(CompileError::without_span(format!(
                "source_hash mismatch for '{}/{}@{}': expected '{}', got '{}'",
                resolved_namespace, name, tagged_version.version, tagged_version.source_hash, computed_source_hash
            )));
        }

        // 6. Read Cell.toml and resolve transitive dependencies
        let manifest_path = package_dir.join("Cell.toml");
        if !manifest_path.exists() {
            return Err(CompileError::without_span(format!(
                "registry package '{}/{}' does not contain Cell.toml",
                resolved_namespace, name
            )));
        }

        let content = std::fs::read_to_string(&manifest_path)?;
        let manifest: PackageManifest = toml::from_str(&content)?;
        validate_declarations(&manifest.artifacts)?;
        if manifest.package.name != name {
            return Err(CompileError::without_span(format!(
                "registry package '{}/{}@{}' Cell.toml declares package name '{}'",
                resolved_namespace, name, tagged_version.version, manifest.package.name
            )));
        }
        if manifest.package.version != tagged_version.version {
            return Err(CompileError::without_span(format!(
                "registry package '{}/{}' selected version '{}' does not match Cell.toml version '{}'",
                resolved_namespace, name, tagged_version.version, manifest.package.version
            )));
        }
        if manifest.package.namespace.as_deref() != Some(resolved_namespace.as_str()) {
            return Err(CompileError::without_span(format!(
                "registry package '{}/{}@{}' Cell.toml must declare namespace '{}'",
                resolved_namespace, name, tagged_version.version, resolved_namespace
            )));
        }
        if manifest.package.cellscript_version != tagged_version.compiler_requirement {
            return Err(CompileError::without_span(format!(
                "registry package '{}/{}@{}' compiler requirement '{}' does not match Cell.toml '{}'",
                resolved_namespace,
                name,
                tagged_version.version,
                tagged_version.compiler_requirement,
                manifest.package.cellscript_version
            ))
            .with_code("E2600"));
        }

        Ok((
            ResolvedPackage {
                node_id: String::new(),
                name: name.to_string(),
                version: manifest.package.version.clone(),
                path: package_dir,
                source: PackageSource::Registry {
                    registry: registry_url,
                    url: source_url,
                    revision,
                    namespace: resolved_namespace.clone(),
                    version: manifest.package.version.clone(),
                },
                dependencies: BTreeMap::new(),
                namespace: Some(resolved_namespace),
                source_hash: Some(computed_source_hash),
                manifest_digest: manifest_digest(content.as_bytes()),
                compiler_requirement: manifest.package.cellscript_version.clone(),
            },
            manifest,
        ))
    }

    fn registry_cache_dir(&self) -> PathBuf {
        self.root.join(".cell/registry-cache")
    }

    pub fn resolve_from_path(&self, name: &str, path: &str) -> Result<ResolvedPackage> {
        let (resolved, _) = self.resolve_from_path_at(name, path, &self.root)?;
        Ok(resolved)
    }

    fn resolve_from_path_at(&self, name: &str, path: &str, base_root: &Path) -> Result<(ResolvedPackage, PackageManifest)> {
        let requested_path = base_root.join(path);
        let package_path = canonical_path(&requested_path).map_err(|_| {
            CompileError::without_span(format!("Dependency '{}' not found at path '{}'", name, requested_path.display()))
        })?;
        let manifest_path = package_path.join("Cell.toml");

        if !manifest_path.exists() {
            return Err(CompileError::without_span(format!("Dependency '{}' not found at path '{}'", name, path)));
        }

        let content = std::fs::read_to_string(&manifest_path)?;
        let manifest: PackageManifest = toml::from_str(&content)?;
        validate_declarations(&manifest.artifacts)?;
        let source_hash = registry::compute_source_hash(&package_path)?;

        let canonical_root = canonical_path(&self.root)?;
        let source_path = relative_path(&canonical_root, &package_path).unwrap_or_else(|| package_path.clone());

        Ok((
            ResolvedPackage {
                node_id: String::new(),
                name: name.to_string(),
                version: manifest.package.version.clone(),
                path: package_path,
                source: PackageSource::Local(source_path),
                dependencies: BTreeMap::new(),
                namespace: manifest.package.namespace.clone(),
                source_hash: Some(source_hash),
                manifest_digest: manifest_digest(content.as_bytes()),
                compiler_requirement: manifest.package.cellscript_version.clone(),
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
            let checkout_ref = detailed.branch.as_ref().map(|branch| format!("origin/{branch}")).unwrap_or_else(|| ref_str.clone());
            Self::git_checkout(&clone_dir, &checkout_ref).map_err(|e| {
                CompileError::without_span(format!("git dependency '{}' failed to checkout '{}': {}", name, checkout_ref, e))
            })?;
        }

        let revision = Self::git_revision(&clone_dir).map_err(|error| {
            CompileError::without_span(format!("git dependency '{}' could not resolve an immutable revision: {}", name, error))
        })?;
        if revision.len() != 40 || !revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(CompileError::without_span(format!(
                "git dependency '{}' resolved non-canonical revision '{}'; expected a full 40-hex commit",
                name, revision
            )));
        }
        let immutable_dir = cache_dir.join(format!("{}-git-{}", name, revision));
        if immutable_dir.exists() {
            let cached_revision = Self::git_revision(&immutable_dir).map_err(CompileError::without_span)?;
            if cached_revision != revision {
                return Err(CompileError::without_span(format!(
                    "immutable git cache '{}' has revision '{}', expected '{}'",
                    immutable_dir.display(),
                    cached_revision,
                    revision
                )));
            }
        } else {
            Self::git_materialize_immutable(&clone_dir, &immutable_dir, &revision).map_err(|error| {
                CompileError::without_span(format!("failed to materialize immutable git dependency '{}': {}", name, error))
            })?;
        }

        let manifest_path = immutable_dir.join("Cell.toml");
        if !manifest_path.exists() {
            return Err(CompileError::without_span(format!(
                "git dependency '{}' from '{}' does not contain Cell.toml at repository root",
                name, url
            )));
        }

        let content = std::fs::read_to_string(&manifest_path)?;
        let manifest: PackageManifest = toml::from_str(&content)?;
        validate_declarations(&manifest.artifacts)?;
        let source_hash = registry::compute_source_hash(&immutable_dir)?;

        Ok((
            ResolvedPackage {
                node_id: String::new(),
                name: name.to_string(),
                version: manifest.package.version.clone(),
                path: immutable_dir,
                source: PackageSource::Git { url: url.to_string(), revision },
                dependencies: BTreeMap::new(),
                namespace: manifest.package.namespace.clone(),
                source_hash: Some(source_hash),
                manifest_digest: manifest_digest(content.as_bytes()),
                compiler_requirement: manifest.package.cellscript_version.clone(),
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
            return Err(format!("git fetch failed for {}: {}", clone_dir.display(), stderr.trim()));
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

    fn git_materialize_immutable(source: &Path, target: &Path, revision: &str) -> std::result::Result<(), String> {
        let output = std::process::Command::new("git")
            .args(["clone", "--no-checkout", "--no-hardlinks", &source.to_string_lossy(), &target.to_string_lossy()])
            .output()
            .map_err(|error| format!("failed to clone immutable cache: {error}"))?;
        if !output.status.success() {
            return Err(format!("git clone failed: {}", String::from_utf8_lossy(&output.stderr).trim()));
        }
        let output = std::process::Command::new("git")
            .args(["checkout", "--detach", revision])
            .current_dir(target)
            .output()
            .map_err(|error| format!("failed to checkout immutable revision: {error}"))?;
        if !output.status.success() {
            let _ = std::fs::remove_dir_all(target);
            return Err(format!("git checkout failed: {}", String::from_utf8_lossy(&output.stderr).trim()));
        }
        Ok(())
    }

    fn git_materialize_locked(url: &str, target: &Path, revision: &str) -> std::result::Result<(), String> {
        let output = std::process::Command::new("git")
            .args(["clone", "--no-checkout", url, &target.to_string_lossy()])
            .output()
            .map_err(|error| format!("failed to clone locked git source: {error}"))?;
        if !output.status.success() {
            return Err(format!("git clone failed: {}", String::from_utf8_lossy(&output.stderr).trim()));
        }
        let output = std::process::Command::new("git")
            .args(["checkout", "--detach", revision])
            .current_dir(target)
            .output()
            .map_err(|error| format!("failed to checkout locked git revision: {error}"))?;
        if !output.status.success() {
            let _ = std::fs::remove_dir_all(target);
            return Err(format!("git checkout failed: {}", String::from_utf8_lossy(&output.stderr).trim()));
        }
        Ok(())
    }

    pub fn get_resolved(&self) -> &BTreeMap<String, ResolvedPackage> {
        &self.resolved
    }

    pub fn root_dependencies(&self) -> &BTreeMap<String, String> {
        &self.root_dependencies
    }

    pub fn build_dependency_graph(&self) -> DependencyGraph {
        let mut graph = DependencyGraph::new();

        for (node_id, package) in &self.resolved {
            graph.add_node(node_id.clone());
            for dependency_id in package.dependencies.values() {
                graph.add_edge(node_id.clone(), dependency_id.clone());
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

fn locked_source_to_package_source(source: &LockedSource) -> PackageSource {
    match source {
        LockedSource::Path { path } => PackageSource::Local(PathBuf::from(path)),
        LockedSource::Git { url, revision } => PackageSource::Git { url: url.clone(), revision: revision.clone() },
        LockedSource::Registry { registry, url, revision, namespace, version } => PackageSource::Registry {
            registry: registry.clone(),
            url: url.clone(),
            revision: revision.clone(),
            namespace: namespace.clone(),
            version: version.clone(),
        },
    }
}

fn validate_locked_root_compiler_contract(lockfile: &Lockfile, manifest: &PackageManifest) -> Result<()> {
    if lockfile.package.compiler_requirement != manifest.package.cellscript_version {
        return Err(CompileError::without_span(format!(
            "Cell.lock compiler requirement '{}' does not match Cell.toml '{}'; run 'cellc update' explicitly",
            lockfile.package.compiler_requirement, manifest.package.cellscript_version
        ))
        .with_code("E2600")
        .with_details(serde_json::json!({
            "package": manifest.package.name,
            "package_version": manifest.package.version,
            "locked_compiler_requirement": lockfile.package.compiler_requirement,
            "compiler_requirement": manifest.package.cellscript_version,
            "active_compiler_version": crate::VERSION,
            "incoming_edge": serde_json::Value::Null,
            "phase": "locked-root-validation",
        })));
    }
    // `validate_manifest_package_contract` already checked the active compiler.
    // Keep the lock's resolver version informational so a later compatible
    // compiler can reproduce locked source selection without an exact pin.
    Ok(())
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
            if !visited.contains_key(node)
                && let Some(cycle) = self.dfs_find_cycle(node, &mut visited, &mut rec_stack)
            {
                return Some(cycle);
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
    pub schema: String,
    #[serde(default)]
    pub resolver_model: String,
    pub package: LockfilePackageInfo,
    pub root: LockedRootGraph,
    pub dependencies: BTreeMap<String, LockedDependency>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub environments: BTreeMap<String, LockedEnvironment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_build: Option<LockedBuildInfo>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub deployment: BTreeMap<String, LockfileDeploymentRef>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LockedRootGraph {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub manifest_digest: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub dependencies: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub dev_dependencies: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockedEnvironment {
    pub chain_id: String,
    pub genesis_hash: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub dependencies: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub dev_dependencies: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LockfilePackageInfo {
    pub edition: CellScriptEdition,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compiler_source_hash: Option<String>,
    /// Source compatibility range declared by `[package].cellscript_version`.
    #[serde(default)]
    pub compiler_requirement: String,
    /// Compiler release that resolved this lock graph. This is evidence, not
    /// an exact build pin; locked builds revalidate `compiler_requirement`.
    #[serde(default)]
    pub resolver_compiler_version: String,
}

/// A reference from Cell.lock [deployment.<network>] to a Deployed.toml entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockfileDeploymentRef {
    pub record: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub out_point: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_hash: Option<String>,
}

impl Lockfile {
    pub const CURRENT_VERSION: u32 = 5;
    pub const CURRENT_SCHEMA: &'static str = "cellscript-lock-v0.30-single-package-coordinate-v1";
    pub const CURRENT_RESOLVER_MODEL: &'static str = "single-package-coordinate-v1";

    pub fn new() -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            schema: Self::CURRENT_SCHEMA.to_string(),
            resolver_model: Self::CURRENT_RESOLVER_MODEL.to_string(),
            package: LockfilePackageInfo {
                compiler_requirement: "*".to_string(),
                resolver_compiler_version: crate::VERSION.to_string(),
                ..LockfilePackageInfo::default()
            },
            root: LockedRootGraph::default(),
            dependencies: BTreeMap::new(),
            environments: BTreeMap::new(),
            package_build: None,
            deployment: BTreeMap::new(),
        }
    }

    pub fn read_from_root(root: &Path) -> Result<Option<Self>> {
        let lock_path = root.join("Cell.lock");
        if !lock_path.exists() {
            return Ok(None);
        }
        let content = std::fs::read_to_string(&lock_path)
            .map_err(|error| CompileError::without_span(format!("failed to read lockfile '{}': {}", lock_path.display(), error)))?;
        let lockfile: Self = toml::from_str(&content)
            .map_err(|error| CompileError::without_span(format!("failed to parse lockfile '{}': {}", lock_path.display(), error)))?;
        lockfile.validate_schema()?;
        Ok(Some(lockfile))
    }

    pub fn write_to_root(&self, root: &Path) -> Result<()> {
        self.validate_schema()?;
        let lock_path = root.join("Cell.lock");
        let content = toml::to_string_pretty(self)?;
        std::fs::write(&lock_path, content)?;
        Ok(())
    }

    pub fn validate_schema(&self) -> Result<()> {
        if self.version != Self::CURRENT_VERSION {
            return Err(CompileError::without_span(format!(
                "unsupported Cell.lock version {}; expected {}",
                self.version,
                Self::CURRENT_VERSION
            )));
        }
        if self.schema != Self::CURRENT_SCHEMA {
            return Err(CompileError::without_span(format!(
                "unsupported Cell.lock schema '{}'; expected '{}'",
                self.schema,
                Self::CURRENT_SCHEMA
            )));
        }
        if self.resolver_model != Self::CURRENT_RESOLVER_MODEL {
            return Err(CompileError::without_span(format!(
                "unsupported Cell.lock resolver model '{}'; expected '{}'",
                self.resolver_model,
                Self::CURRENT_RESOLVER_MODEL
            ))
            .with_code("E2601"));
        }
        if self.package.compiler_requirement.is_empty() || self.package.resolver_compiler_version.is_empty() {
            return Err(CompileError::without_span(
                "Cell.lock v5 package requires compiler_requirement and resolver_compiler_version; run 'cellc lock' or 'cellc update' explicitly",
            )
            .with_code("E2600"));
        }
        parse_compiler_requirement(&self.package.compiler_requirement)?;
        semver::Version::parse(&self.package.resolver_compiler_version).map_err(|error| {
            CompileError::without_span(format!(
                "Cell.lock package resolver_compiler_version '{}' is invalid: {error}",
                self.package.resolver_compiler_version
            ))
        })?;
        if let Some(build) = &self.package_build {
            if build.edition != self.package.edition {
                return Err(CompileError::without_span(format!(
                    "Cell.lock package/build edition mismatch: package is '{}' but build is '{}'",
                    self.package.edition, build.edition
                )));
            }
            if build.compatibility_profile_hash.is_empty() {
                return Err(CompileError::without_span("Cell.lock v5 package_build requires compatibility_profile_hash"));
            }
        }
        self.validate_graph()?;
        Ok(())
    }

    fn validate_graph(&self) -> Result<()> {
        for (node_id, dependency) in &self.dependencies {
            if dependency.name.is_empty()
                || dependency.manifest_digest.is_empty()
                || dependency.source_hash.as_deref().is_none_or(str::is_empty)
                || dependency.compiler_requirement.is_empty()
                || dependency.resolver_compiler_version.is_empty()
            {
                return Err(CompileError::without_span(format!(
                    "Cell.lock dependency node '{}' requires name, manifest_digest, source_hash, compiler_requirement, and resolver_compiler_version",
                    node_id
                ))
                .with_code("E2600"));
            }
            parse_compiler_requirement(&dependency.compiler_requirement)?;
            semver::Version::parse(&dependency.resolver_compiler_version).map_err(|error| {
                CompileError::without_span(format!(
                    "Cell.lock dependency node '{}' resolver_compiler_version '{}' is invalid: {error}",
                    node_id, dependency.resolver_compiler_version
                ))
            })?;
            for (alias, target) in &dependency.dependencies {
                if !self.dependencies.contains_key(target) {
                    return Err(CompileError::without_span(format!(
                        "Cell.lock dependency node '{}' edge '{}' targets missing node '{}'",
                        node_id, alias, target
                    )));
                }
            }
        }
        self.validate_root_edges("root dependencies", &self.root.dependencies)?;
        self.validate_root_edges("root dev-dependencies", &self.root.dev_dependencies)?;
        for (name, environment) in &self.environments {
            validate_environment(
                name,
                &CkbEnvironment { chain_id: environment.chain_id.clone(), genesis_hash: environment.genesis_hash.clone() },
            )?;
            self.validate_root_edges(&format!("environment '{}' dependencies", name), &environment.dependencies)?;
            self.validate_root_edges(&format!("environment '{}' dev-dependencies", name), &environment.dev_dependencies)?;
        }
        let graph = self.dependency_graph();
        if let Some(cycle) = graph.find_cycle() {
            return Err(CompileError::without_span(format!("Cell.lock dependency graph contains a cycle: {}", cycle.join(" -> "))));
        }
        Ok(())
    }

    fn validate_root_edges(&self, label: &str, edges: &BTreeMap<String, String>) -> Result<()> {
        for (alias, target) in edges {
            if !self.dependencies.contains_key(target) {
                return Err(CompileError::without_span(format!(
                    "Cell.lock {} edge '{}' targets missing node '{}'",
                    label, alias, target
                )));
            }
        }
        Ok(())
    }

    fn dependency_graph(&self) -> DependencyGraph {
        let mut graph = DependencyGraph::new();
        for (node_id, dependency) in &self.dependencies {
            graph.add_node(node_id.clone());
            for target in dependency.dependencies.values() {
                graph.add_edge(node_id.clone(), target.clone());
            }
        }
        graph
    }

    pub fn update_from_resolved(&mut self, resolved: &BTreeMap<String, ResolvedPackage>) {
        for (node_id, package) in resolved {
            let locked = LockedDependency {
                name: package.name.clone(),
                namespace: package.namespace.clone(),
                version: package.version.clone(),
                source: match &package.source {
                    PackageSource::Local(path) => LockedSource::Path { path: path.to_string_lossy().to_string() },
                    PackageSource::Git { url, revision } => LockedSource::Git { url: url.clone(), revision: revision.clone() },
                    PackageSource::Registry { registry, url, revision, namespace, version } => LockedSource::Registry {
                        registry: registry.clone(),
                        url: url.clone(),
                        revision: revision.clone(),
                        namespace: namespace.clone(),
                        version: version.clone(),
                    },
                },
                source_hash: package.source_hash.clone(),
                manifest_digest: package.manifest_digest.clone(),
                dependencies: package.dependencies.clone(),
                build: None,
                compiler_requirement: package.compiler_requirement.clone(),
                resolver_compiler_version: crate::VERSION.to_string(),
            };
            self.dependencies.insert(node_id.clone(), locked);
        }
    }

    pub fn replace_with_resolved(&mut self, resolved: &BTreeMap<String, ResolvedPackage>) {
        self.dependencies.clear();
        self.update_from_resolved(resolved);
    }

    pub fn replace_with_resolution(
        &mut self,
        manager: &PackageManager,
        manifest: &PackageManifest,
        options: &ResolutionOptions,
    ) -> Result<()> {
        self.dependencies.clear();
        self.root = LockedRootGraph::default();
        self.environments.clear();
        self.merge_resolution(manager, manifest, options)
    }

    pub fn merge_resolution(
        &mut self,
        manager: &PackageManager,
        manifest: &PackageManifest,
        options: &ResolutionOptions,
    ) -> Result<()> {
        self.package.edition = manifest.package.edition;
        self.package.name = manifest.package.name.clone();
        self.package.version = manifest.package.version.clone();
        self.package.namespace = manifest.package.namespace.clone();
        self.package.compiler_requirement = manifest.package.cellscript_version.clone();
        self.package.resolver_compiler_version = crate::VERSION.to_string();
        self.update_from_resolved(manager.get_resolved());
        let manifest_bytes = std::fs::read(manager.root.join("Cell.toml"))?;
        self.root.manifest_digest = manifest_digest(&manifest_bytes);

        let mut runtime = BTreeMap::new();
        let mut dev = BTreeMap::new();
        for (alias, node_id) in manager.root_dependencies() {
            if options.scope == DependencyScope::Test && manifest.dev_dependencies.contains_key(alias) {
                dev.insert(alias.clone(), node_id.clone());
            } else {
                runtime.insert(alias.clone(), node_id.clone());
            }
        }

        if let Some(environment_name) = options.environment.as_deref() {
            let environment = manifest
                .environments
                .get(environment_name)
                .ok_or_else(|| CompileError::without_span(format!("unknown package environment '{}'", environment_name)))?;
            self.environments.insert(
                environment_name.to_string(),
                LockedEnvironment {
                    chain_id: environment.chain_id.clone(),
                    genesis_hash: normalized_genesis_hash(&environment.genesis_hash),
                    dependencies: runtime,
                    dev_dependencies: dev,
                },
            );
        } else {
            self.root.dependencies = runtime;
            self.root.dev_dependencies = dev;
        }
        self.validate_schema()
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
        resolved: &BTreeMap<String, ResolvedPackage>,
    ) -> Vec<String> {
        self.consistency_issues_with_expected(manifest, Some(resolved))
    }

    fn consistency_issues_with_expected(
        &self,
        manifest: &PackageManifest,
        resolved: Option<&BTreeMap<String, ResolvedPackage>>,
    ) -> Vec<String> {
        let mut issues = Vec::new();
        if self.version != Self::CURRENT_VERSION {
            issues.push(format!("Cell.lock version {} is not supported; expected {}", self.version, Self::CURRENT_VERSION));
        }
        if self.package.edition != manifest.package.edition {
            issues.push(format!(
                "package edition mismatch: Cell.toml has '{}' but Cell.lock records '{}'",
                manifest.package.edition, self.package.edition
            ));
        }
        if self.package.compiler_requirement != manifest.package.cellscript_version {
            issues.push(format!(
                "package compiler requirement mismatch: Cell.toml has '{}' but Cell.lock records '{}'",
                manifest.package.cellscript_version, self.package.compiler_requirement
            ));
        }

        if manifest.dependency_overrides.is_empty() {
            issues.extend(self.root_graph_consistency_issues(
                "root",
                &manifest.dependencies,
                &manifest.dev_dependencies,
                &self.root.dependencies,
                &self.root.dev_dependencies,
                manifest.package.namespace.as_deref(),
            ));
        }
        for (environment_name, environment) in &manifest.environments {
            let Some(locked_environment) = self.environments.get(environment_name) else {
                issues.push(format!("environment '{}' is missing from Cell.lock", environment_name));
                continue;
            };
            if locked_environment.chain_id != environment.chain_id
                || normalized_genesis_hash(&locked_environment.genesis_hash) != normalized_genesis_hash(&environment.genesis_hash)
            {
                issues.push(format!("environment '{}' chain identity differs between Cell.toml and Cell.lock", environment_name));
            }
            let mut dependencies = manifest.dependencies.clone();
            if let Some(overrides) = manifest.dependency_overrides.get(environment_name) {
                dependencies.extend(overrides.clone());
            }
            issues.extend(self.root_graph_consistency_issues(
                &format!("environment '{}'", environment_name),
                &dependencies,
                &manifest.dev_dependencies,
                &locked_environment.dependencies,
                &locked_environment.dev_dependencies,
                manifest.package.namespace.as_deref(),
            ));
        }

        if let Some(resolved) = resolved {
            for (node_id, package) in resolved {
                let Some(locked) = self.dependencies.get(node_id) else {
                    issues.push(format!("resolved dependency node '{}' is missing from Cell.lock", node_id));
                    continue;
                };
                issues.extend(resolved_dependency_consistency_issues(node_id, package, locked));
            }
        }

        let reachable = self.reachable_nodes();
        for node_id in self.dependencies.keys() {
            if !reachable.contains(node_id) {
                issues.push(format!("Cell.lock contains unreachable dependency node '{}'", node_id));
            }
        }

        issues
    }

    fn root_graph_consistency_issues(
        &self,
        label: &str,
        dependencies: &HashMap<String, Dependency>,
        dev_dependencies: &HashMap<String, Dependency>,
        locked_dependencies: &BTreeMap<String, String>,
        locked_dev_dependencies: &BTreeMap<String, String>,
        namespace: Option<&str>,
    ) -> Vec<String> {
        let mut issues = Vec::new();
        for (alias, dependency) in dependencies {
            let Some(node_id) = locked_dependencies.get(alias) else {
                if !dependency_is_optional(dependency) {
                    issues.push(format!("{} dependency '{}' is missing from Cell.lock", label, alias));
                }
                continue;
            };
            match self.dependencies.get(node_id) {
                Some(locked) => issues.extend(lock_dependency_consistency_issues(alias, dependency, locked, namespace, None)),
                None => issues.push(format!("{} dependency '{}' targets missing node '{}'", label, alias, node_id)),
            }
        }
        for (alias, dependency) in dev_dependencies {
            let Some(node_id) = locked_dev_dependencies.get(alias) else {
                if !dependency_is_optional(dependency) {
                    issues.push(format!("{} dev-dependency '{}' is missing from Cell.lock", label, alias));
                }
                continue;
            };
            match self.dependencies.get(node_id) {
                Some(locked) => issues.extend(lock_dependency_consistency_issues(alias, dependency, locked, namespace, None)),
                None => issues.push(format!("{} dev-dependency '{}' targets missing node '{}'", label, alias, node_id)),
            }
        }
        for alias in locked_dependencies.keys() {
            if !dependencies.contains_key(alias) {
                issues.push(format!("{} contains stale dependency alias '{}'", label, alias));
            }
        }
        for alias in locked_dev_dependencies.keys() {
            if !dev_dependencies.contains_key(alias) {
                issues.push(format!("{} contains stale dev-dependency alias '{}'", label, alias));
            }
        }
        issues
    }

    fn reachable_nodes(&self) -> BTreeSet<String> {
        let mut pending: Vec<String> = self
            .root
            .dependencies
            .values()
            .chain(self.root.dev_dependencies.values())
            .chain(
                self.environments
                    .values()
                    .flat_map(|environment| environment.dependencies.values().chain(environment.dev_dependencies.values())),
            )
            .cloned()
            .collect();
        let mut reachable = BTreeSet::new();
        while let Some(node_id) = pending.pop() {
            if !reachable.insert(node_id.clone()) {
                continue;
            }
            if let Some(node) = self.dependencies.get(&node_id) {
                pending.extend(node.dependencies.values().cloned());
            }
        }
        reachable
    }
}

fn resolved_dependency_consistency_issues(name: &str, package: &ResolvedPackage, locked: &LockedDependency) -> Vec<String> {
    let mut issues = Vec::new();

    if locked.name != package.name {
        issues.push(format!(
            "resolved dependency node '{}' has package name '{}' but Cell.lock records '{}'",
            name, package.name, locked.name
        ));
    }

    if locked.version != package.version {
        issues.push(format!(
            "resolved dependency '{}' has package version '{}' but Cell.lock records '{}'",
            name, package.version, locked.version
        ));
    }

    if locked.manifest_digest != package.manifest_digest {
        issues.push(format!(
            "resolved dependency node '{}' manifest digest '{}' does not match Cell.lock '{}'",
            name, package.manifest_digest, locked.manifest_digest
        ));
    }
    if locked.compiler_requirement != package.compiler_requirement {
        issues.push(format!(
            "resolved dependency node '{}' compiler requirement '{}' does not match Cell.lock '{}'",
            name, package.compiler_requirement, locked.compiler_requirement
        ));
    }
    if locked.dependencies != package.dependencies {
        issues.push(format!("resolved dependency node '{}' edges do not match Cell.lock", name));
    }

    match (&package.source, &locked.source) {
        (PackageSource::Local(path), LockedSource::Path { path: locked_path }) if locked_path == path.to_string_lossy().as_ref() => {}
        (PackageSource::Git { url, revision }, LockedSource::Git { url: locked_url, revision: locked_revision })
            if locked_url == url && locked_revision == revision => {}
        (
            PackageSource::Registry { registry, url, revision, namespace, version },
            LockedSource::Registry {
                registry: locked_registry,
                url: locked_url,
                revision: locked_revision,
                namespace: locked_namespace,
                version: locked_version,
            },
        ) if locked_registry == registry
            && locked_url == url
            && locked_revision == revision
            && locked_namespace == namespace
            && locked_version == version => {}
        (_, source) => issues.push(format!(
            "resolved dependency '{}' expects {} but Cell.lock records {}",
            name,
            package_source_display(&package.source),
            locked_source_display(source)
        )),
    }

    if let Some(expected_hash) = &package.source_hash {
        match &locked.source_hash {
            Some(locked_hash) if locked_hash == expected_hash => {}
            Some(locked_hash) => issues.push(format!(
                "resolved dependency '{}' source_hash '{}' does not match Cell.lock '{}'",
                name, expected_hash, locked_hash
            )),
            None => issues.push(format!("resolved dependency '{}' is missing source_hash in Cell.lock", name)),
        }
    } else {
        issues.push(format!("resolved dependency '{}' did not produce a source_hash", name));
    }

    issues
}

fn lock_dependency_consistency_issues(
    name: &str,
    dep: &Dependency,
    locked: &LockedDependency,
    consuming_namespace: Option<&str>,
    path_context: Option<(&Path, &Path)>,
) -> Vec<String> {
    let mut issues = Vec::new();
    let expected_package = dependency_package_name(name, dep);
    if locked.name != expected_package {
        issues.push(format!(
            "dependency alias '{}' expects package '{}' but Cell.lock node declares '{}'",
            name, expected_package, locked.name
        ));
    }

    match dep {
        Dependency::Simple(version) => match &locked.source {
            LockedSource::Registry { namespace: locked_namespace, version: locked_version, .. }
                if Some(locked_namespace.as_str()) == consuming_namespace && locked_version == &locked.version => {}
            source => issues.push(format!(
                "dependency '{}' expects registry source {}@{} but Cell.lock records {}",
                name,
                name,
                version,
                locked_source_display(source)
            )),
        },
        Dependency::Detailed(detail) => {
            if detail.resolver.is_some() {
                // Update-time resolvers are normalized into the immutable
                // source recorded here. Locked builds never invoke them.
            } else if let Some(path) = &detail.path {
                match &locked.source {
                    LockedSource::Path { path: locked_path }
                        if path_context.map_or_else(
                            || locked_path == path,
                            |(manifest_root, workspace_root)| {
                                canonical_path(&manifest_root.join(path)).ok()
                                    == canonical_path(&workspace_root.join(locked_path)).ok()
                            },
                        ) => {}
                    source => issues.push(format!(
                        "dependency '{}' expects path source '{}' but Cell.lock records {}",
                        name,
                        path,
                        locked_source_display(source)
                    )),
                }
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
            } else {
                match &locked.source {
                    LockedSource::Registry { namespace: locked_namespace, version: locked_version, .. }
                        if Some(locked_namespace.as_str()) == detail.namespace.as_deref().or(consuming_namespace)
                            && locked_version == &locked.version => {}
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

    if let Some(requirement) = match dep {
        Dependency::Simple(requirement) => Some(requirement.as_str()),
        Dependency::Detailed(detail) if detail.version != "*" && !detail.version.is_empty() => Some(detail.version.as_str()),
        Dependency::Detailed(_) => None,
    } {
        match version::parse_version_req(requirement) {
            Ok(requirement) if version::satisfies(&locked.version, &requirement) => {}
            Ok(_) => issues.push(format!(
                "dependency '{}' requires '{}' but Cell.lock records package version '{}'",
                name, requirement, locked.version
            )),
            Err(error) => issues.push(error.message.clone()),
        }
    }

    issues
}

fn locked_source_display(source: &LockedSource) -> String {
    match source {
        LockedSource::Path { path } => format!("path '{}'", path),
        LockedSource::Git { url, revision } => format!("git '{}#{}'", url, revision),
        LockedSource::Registry { registry, namespace, version, .. } => format!("registry {}/{}@{}", registry, namespace, version),
    }
}

fn package_source_display(source: &PackageSource) -> String {
    match source {
        PackageSource::Local(path) => format!("path '{}'", path.display()),
        PackageSource::Git { url, revision } => format!("git '{}#{}'", url, revision),
        PackageSource::Registry { registry, namespace, version, .. } => format!("registry {}/{}@{}", registry, namespace, version),
    }
}

impl Default for Lockfile {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LockedBuildInfo {
    pub edition: CellScriptEdition,
    pub compatibility_profile_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compiler_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cell_data_codec_manifest_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub abi_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constraints_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockedDependency {
    #[serde(default)]
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    pub version: String,
    pub source: LockedSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_hash: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub manifest_digest: String,
    /// Source compatibility range declared by the dependency manifest.
    #[serde(default)]
    pub compiler_requirement: String,
    /// Compiler release that resolved this dependency node.
    #[serde(default)]
    pub resolver_compiler_version: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub dependencies: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build: Option<LockedBuildInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LockedSource {
    Path { path: String },
    Git { url: String, revision: String },
    Registry { registry: String, url: String, revision: String, namespace: String, version: String },
}

pub mod version {
    use super::*;

    pub fn parse_version_req(req: &str) -> Result<VersionReq> {
        let req = req.trim();
        let parsed = if req == "*" {
            VersionReq::Any
        } else if let Some(stripped) = req.strip_prefix('^') {
            VersionReq::Compatible(stripped.to_string())
        } else if let Some(stripped) = req.strip_prefix('=') {
            VersionReq::Exact(stripped.to_string())
        } else if req.contains(',') || req.contains('>') || req.contains('<') || req.contains('~') {
            VersionReq::Range(req.to_string())
        } else {
            // Preserve CellScript's historical bare-version-as-compatible
            // surface while using the standard SemVer compatibility rules.
            VersionReq::Compatible(req.to_string())
        };
        standard_requirement(&parsed)?;
        Ok(parsed)
    }

    pub fn satisfies(version: &str, req: &VersionReq) -> bool {
        let Ok(version) = semver::Version::parse(version) else {
            return false;
        };
        standard_requirement(req).is_ok_and(|requirement| requirement.matches(&version))
    }

    fn standard_requirement(req: &VersionReq) -> Result<semver::VersionReq> {
        let source = match req {
            VersionReq::Any => "*".to_string(),
            VersionReq::Exact(version) => format!("={version}"),
            VersionReq::Compatible(version) => format!("^{version}"),
            VersionReq::Range(range) => range.clone(),
        };
        semver::VersionReq::parse(&source)
            .map_err(|error| CompileError::without_span(format!("invalid semantic version requirement '{source}': {error}")))
    }
}

// ---------------------------------------------------------------------------
// Deployed.toml — Deployment Fact Record
// ---------------------------------------------------------------------------

/// The only supported Deployed.toml schema for edition 2026.
pub const DEPLOYED_MANIFEST_SCHEMA: &str = "cellscript-deployed-v0.23-edition-2026";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployedManifest {
    pub version: u32,
    pub schema: String,
    pub package: DeployedPackageInfo,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build: Option<DeployedBuildInfo>,
    #[serde(default)]
    pub deployments: Vec<DeploymentRecord>,
}

impl DeployedManifest {
    pub const CURRENT_VERSION: u32 = 2;

    pub fn read_from_root(root: &Path) -> Result<Option<Self>> {
        let path = root.join("Deployed.toml");
        if !path.exists() {
            return Ok(None);
        }
        let content = std::fs::read_to_string(&path)
            .map_err(|e| CompileError::without_span(format!("failed to read Deployed.toml '{}': {}", path.display(), e)))?;
        let manifest: Self = toml::from_str(&content)
            .map_err(|e| CompileError::without_span(format!("failed to parse Deployed.toml '{}': {}", path.display(), e)))?;
        manifest.validate_schema()?;
        Ok(Some(manifest))
    }

    pub fn write_to_root(&self, root: &Path) -> Result<()> {
        self.validate_schema()?;
        let path = root.join("Deployed.toml");
        let content = toml::to_string_pretty(self)?;
        std::fs::write(&path, content)?;
        Ok(())
    }

    pub fn validate_schema(&self) -> Result<()> {
        if self.version != Self::CURRENT_VERSION || self.schema != DEPLOYED_MANIFEST_SCHEMA {
            return Err(CompileError::without_span(format!(
                "unsupported Deployed.toml identity; expected version {} and schema '{}'",
                Self::CURRENT_VERSION,
                DEPLOYED_MANIFEST_SCHEMA
            )));
        }
        if let Some(build) = &self.build {
            if build.edition != self.package.edition {
                return Err(CompileError::without_span(format!(
                    "Deployed.toml package/build edition mismatch: package is '{}' but build is '{}'",
                    self.package.edition, build.edition
                )));
            }
            if build.compatibility_profile_hash.is_empty() {
                return Err(CompileError::without_span("Deployed.toml v2 build requires compatibility_profile_hash"));
            }
        }
        for deployment in &self.deployments {
            if deployment.edition != self.package.edition {
                return Err(CompileError::without_span(format!(
                    "Deployed.toml package/deployment edition mismatch for network '{}': package is '{}' but deployment is '{}'",
                    deployment.network, self.package.edition, deployment.edition
                )));
            }
            if deployment.compatibility_profile_hash.is_empty() {
                return Err(CompileError::without_span(format!(
                    "Deployed.toml v2 deployment for network '{}' requires compatibility_profile_hash",
                    deployment.network
                )));
            }
            if let Some(build) = &self.build
                && deployment.compatibility_profile_hash != build.compatibility_profile_hash
            {
                return Err(CompileError::without_span(format!(
                    "Deployed.toml build/deployment compatibility profile mismatch for network '{}'",
                    deployment.network
                )));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployedPackageInfo {
    pub name: String,
    pub version: String,
    pub edition: CellScriptEdition,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_hash: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeployedBuildInfo {
    pub edition: CellScriptEdition,
    pub compatibility_profile_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compiler_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cell_data_codec_manifest_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub abi_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constraints_hash: Option<String>,
}

/// Deployment status lifecycle:
/// candidate -> active -> deprecated -> revoked
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeploymentStatus {
    #[default]
    Candidate,
    Active,
    Deprecated,
    Revoked,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScriptRole {
    #[default]
    Type,
    Lock,
    DualRole,
    Helper,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentRecord {
    // Required fields (Phase 1)
    pub edition: CellScriptEdition,
    pub network: String,
    pub chain_id: String,
    pub tx_hash: String,
    pub output_index: u32,
    pub code_hash: String,
    pub hash_type: String,
    pub dep_type: String,
    pub data_hash: String,
    pub out_point: String,

    // Recommended fields (Phase 1 — build provenance binding)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cell_data_codec_manifest_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub abi_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constraints_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compiler_version: Option<String>,
    pub compatibility_profile_hash: String,

    // Optional fields (Phase 2 — governance and upgrade)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub type_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script_role: Option<ScriptRole>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<DeploymentStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upgrade_lineage: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_report_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publisher_signature: Option<String>,

    // Cell deps
    #[serde(default)]
    pub cell_deps: Vec<DeploymentCellDep>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentCellDep {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub tx_hash: String,
    pub output_index: u32,
    pub dep_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub type_id: Option<String>,
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
                edition: CURRENT_EDITION,
                namespace: None,
                authors: vec!["Test Author".to_string()],
                description: "Test package".to_string(),
                license: "MIT".to_string(),
                repository: String::new(),
                homepage: String::new(),
                documentation: String::new(),
                keywords: vec!["test".to_string()],
                categories: vec!["test".to_string()],
                cellscript_version: "*".to_string(),
                entry: "src/main.cell".to_string(),
                source_roots: vec![],
                include: vec![],
                exclude: vec![],
            },
            workspace: None,
            artifacts: Vec::new(),
            dependencies: HashMap::new(),
            dev_dependencies: HashMap::new(),
            features: BTreeMap::new(),
            environments: BTreeMap::new(),
            dependency_overrides: BTreeMap::new(),
            resolvers: BTreeMap::new(),
            build: BuildConfig::default(),
            policy: PolicyConfig::default(),
            deploy: DeployConfig::default(),
            metadata: HashMap::new(),
        };

        let toml_str = toml::to_string(&manifest).unwrap();
        assert!(toml_str.contains("name = \"test\""));
        assert!(toml_str.contains("version = \"0.1.0\""));
        assert!(toml_str.contains("edition = \"2026\""));
        let parsed: PackageManifest = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.package.edition, CURRENT_EDITION);
        assert!(parsed.artifacts.is_empty());
        assert!(!toml_str.contains("artifacts"));
    }

    #[test]
    fn policy_artifact_manifest_roundtrip_preserves_explicit_tags_and_common_order() {
        let dir = tempdir().unwrap();
        let manager = PackageManager::new(dir.path());
        manager.init("policy_fixture").unwrap();
        let mut manifest = manager.read_manifest().unwrap();
        let declaration: ArtifactDeclaration = toml::from_str(
            r#"
name = "token-policy"
context = { kind = "type-group", resource = "Token" }
dispatch = "policy-witness-v1"
actions = [{ tag = 40, action = "burn" }, { tag = 10, action = "mint" }]
common_checks = ["authenticate", "audit"]
"#,
        )
        .unwrap();
        manifest.artifacts.push(declaration.clone());
        manager.write_manifest(&manifest).unwrap();
        let loaded = manager.read_manifest().unwrap();
        assert_eq!(loaded.artifacts, vec![declaration]);
        let encoded = std::fs::read_to_string(dir.path().join("Cell.toml")).unwrap();
        assert!(encoded.contains("[[artifacts]]"));
        assert_eq!(loaded.artifacts[0].actions[0].tag, 40);
        assert_eq!(loaded.artifacts[0].common_checks, ["authenticate", "audit"]);
    }

    #[test]
    fn policy_artifact_manifest_rejects_duplicate_names_tags_and_unknown_contract_fields() {
        let dir = tempdir().unwrap();
        let manager = PackageManager::new(dir.path());
        manager.init("policy_fixture").unwrap();
        let base = std::fs::read_to_string(dir.path().join("Cell.toml")).unwrap();
        let valid = r#"
[[artifacts]]
name = "token-policy"
context = { kind = "type-group", resource = "Token" }
dispatch = "policy-witness-v1"
actions = [{ tag = 10, action = "mint" }, { tag = 20, action = "burn" }]
"#;
        for (suffix, expected) in [
            (format!("{valid}{valid}"), "declared more than once"),
            (valid.replace("tag = 20", "tag = 10"), "repeats numeric tag"),
            (format!("{valid}fallback = true\n"), "unknown field"),
            (valid.replace("type-group", "lock-group"), "unknown variant"),
            (valid.replace("policy-witness-v1", "policy-witness-v2"), "unknown variant"),
        ] {
            std::fs::write(dir.path().join("Cell.toml"), format!("{base}{suffix}")).unwrap();
            let error = manager.read_manifest().unwrap_err();
            assert!(error.message.contains(expected), "{expected}: {}", error.message);
        }
        let mut manifest: PackageManifest = toml::from_str(&format!("{base}{valid}")).unwrap();
        manifest.artifacts.push(manifest.artifacts[0].clone());
        assert!(manager.write_manifest(&manifest).unwrap_err().message.contains("declared more than once"));
        assert!(manager.validate_manifest_package_contract(&manifest).unwrap_err().message.contains("declared more than once"));
    }

    #[test]
    fn package_manifest_requires_a_known_explicit_edition() {
        let missing = toml::from_str::<PackageManifest>(
            r#"
[package]
name = "demo"
version = "0.1.0"
"#,
        )
        .unwrap_err();
        assert!(missing.to_string().contains("missing field `edition`"));

        let unsupported = toml::from_str::<PackageManifest>(
            r#"
[package]
edition = "unsupported"
name = "demo"
version = "0.1.0"
"#,
        )
        .unwrap_err();
        let message = unsupported.to_string();
        assert!(message.contains("2026") && message.contains("2027"));

        let preview = toml::from_str::<PackageManifest>(
            r#"
[package]
edition = "2027"
name = "demo"
version = "0.1.0"
"#,
        )
        .unwrap();
        assert_eq!(preview.package.edition, crate::NEXT_EDITION);
    }

    #[test]
    fn package_manager_init_writes_current_edition() {
        let temp = tempdir().unwrap();
        PackageManager::new(temp.path()).init("demo").unwrap();
        let source = std::fs::read_to_string(temp.path().join("Cell.toml")).unwrap();
        assert!(source.contains("edition = \"2026\""));
        assert!(source.contains(&format!("cellscript_version = \">={}\"", crate::VERSION)));
        let manifest: PackageManifest = toml::from_str(&source).unwrap();
        assert_eq!(manifest.package.edition, CURRENT_EDITION);
    }

    #[test]
    fn compiler_requirement_is_semver_checked_and_legacy_bare_versions_are_minimums() {
        assert!(compiler_requirement_matches("*", "0.1.0").unwrap());
        assert!(compiler_requirement_matches("0.16", "0.26.0").unwrap());
        assert!(!compiler_requirement_matches("0.30", "0.29.9").unwrap());
        assert!(compiler_requirement_matches("0.30", "0.30.0").unwrap());
        assert!(!compiler_requirement_matches("^0.30", "0.31.0").unwrap());
        assert!(compiler_requirement_matches(">=0.26.0-alpha.1", "0.26.0").unwrap());
        assert!(compiler_requirement_matches("=0.30.0-alpha.1", "0.30.0-alpha.1").unwrap());
        assert!(!compiler_requirement_matches("=0.30.0-alpha.1", "0.30.0-alpha.2").unwrap());
        assert!(parse_compiler_requirement("").unwrap_err().message.contains("must not be empty"));
        assert!(parse_compiler_requirement("not-semver").unwrap_err().message.contains("invalid package cellscript_version"));

        let incompatible: PackageManifest = toml::from_str(
            r#"
[package]
edition = "2026"
name = "future"
version = "1.0.0"
cellscript_version = ">=999.0.0"
"#,
        )
        .unwrap();
        let error = validate_package_compiler_requirement(&incompatible.package).unwrap_err();
        assert!(error.message.contains("future@1.0.0"), "{}", error.message);
        assert!(error.message.contains(crate::VERSION), "{}", error.message);
    }

    #[test]
    fn transitive_path_package_rejects_incompatible_compiler_before_source_loading() {
        let temp = tempdir().unwrap();
        let root = temp.path();
        std::fs::create_dir_all(root.join("deps/middle/src")).unwrap();
        std::fs::create_dir_all(root.join("deps/future/src")).unwrap();
        std::fs::write(
            root.join("Cell.toml"),
            r#"
[package]
edition = "2026"
name = "app"
version = "1.0.0"

[dependencies.middle]
path = "deps/middle"
"#,
        )
        .unwrap();
        std::fs::write(
            root.join("deps/middle/Cell.toml"),
            r#"
[package]
edition = "2026"
name = "middle"
version = "1.0.0"

[dependencies.future]
path = "../future"
"#,
        )
        .unwrap();
        std::fs::write(root.join("deps/middle/src/lib.cell"), "module middle;\n").unwrap();
        std::fs::write(
            root.join("deps/future/Cell.toml"),
            r#"
[package]
edition = "2026"
name = "future"
version = "1.0.0"
cellscript_version = ">=999.0.0"
"#,
        )
        .unwrap();
        std::fs::write(root.join("deps/future/src/lib.cell"), "this is deliberately invalid CellScript").unwrap();

        let error = PackageManager::new(root).resolve_dependencies().unwrap_err();
        assert_eq!(error.code.as_deref(), Some("E2600"));
        let incompatible = &error.details.as_ref().unwrap()["incompatible_packages"][0];
        assert_eq!(incompatible["package"], "future");
        assert_eq!(incompatible["package_version"], "1.0.0");
        assert_eq!(incompatible["incoming_edge"]["from_package"], "middle");
        assert_eq!(incompatible["incoming_edge"]["alias"], "future");
        assert!(incompatible["message"].as_str().unwrap().contains("before loading source"));
        assert!(!incompatible["message"].as_str().unwrap().contains("parse"));
    }

    #[test]
    fn dependency_preflight_reports_every_incompatible_package_and_incoming_edge() {
        let temp = tempdir().unwrap();
        let root = temp.path();
        for package in ["future_a", "future_b"] {
            let package_root = root.join("deps").join(package);
            std::fs::create_dir_all(package_root.join("src")).unwrap();
            std::fs::write(
                package_root.join("Cell.toml"),
                format!(
                    r#"
[package]
edition = "2026"
name = "{package}"
version = "1.0.0"
cellscript_version = ">=999.0.0"
"#
                ),
            )
            .unwrap();
            std::fs::write(package_root.join("src/lib.cell"), "this source is intentionally invalid").unwrap();
        }
        std::fs::write(
            root.join("Cell.toml"),
            r#"
[package]
edition = "2026"
name = "app"
version = "1.0.0"

[dependencies.first]
package = "future_a"
path = "deps/future_a"

[dependencies.second]
package = "future_b"
path = "deps/future_b"
"#,
        )
        .unwrap();

        let mut manager = PackageManager::new(root);
        let error = manager.resolve_dependencies().unwrap_err();

        assert_eq!(error.code.as_deref(), Some("E2600"));
        let incompatible = error.details.as_ref().unwrap()["incompatible_packages"].as_array().unwrap();
        assert_eq!(incompatible.len(), 2, "{}", error.message);
        assert_eq!(incompatible.iter().map(|entry| entry["package"].as_str().unwrap()).collect::<Vec<_>>(), ["future_a", "future_b"]);
        assert_eq!(incompatible[0]["incoming_edge"]["alias"], "first");
        assert_eq!(incompatible[1]["incoming_edge"]["alias"], "second");
        assert!(manager.get_resolved().is_empty());
    }

    #[test]
    fn aliases_reuse_one_package_coordinate_but_distinct_paths_fail_closed() {
        let temp = tempdir().unwrap();
        let root = temp.path();
        write_path_package(root, "deps/shared", "shared", "1.0.0");
        std::fs::write(
            root.join("Cell.toml"),
            r#"
[package]
edition = "2026"
name = "app"
version = "1.0.0"

[dependencies.first]
package = "shared"
path = "deps/shared"

[dependencies.second]
package = "shared"
path = "deps/shared"
"#,
        )
        .unwrap();
        let mut manager = PackageManager::new(root);
        manager.resolve_dependencies().unwrap();
        assert_eq!(manager.root_dependencies()["first"], manager.root_dependencies()["second"]);
        assert_eq!(manager.get_resolved().values().filter(|package| package.name == "shared").count(), 1);

        write_path_package(root, "deps/substitute", "shared", "1.0.0");
        let manifest = std::fs::read_to_string(root.join("Cell.toml")).unwrap().replace(
            "[dependencies.second]\npackage = \"shared\"\npath = \"deps/shared\"",
            "[dependencies.second]\npackage = \"shared\"\npath = \"deps/substitute\"",
        );
        std::fs::write(root.join("Cell.toml"), manifest).unwrap();
        let error = manager.resolve_dependencies().unwrap_err();
        assert_eq!(error.code.as_deref(), Some("E2601"));
        assert_eq!(error.details.as_ref().unwrap()["conflict_kind"], "source");
        assert_eq!(error.details.as_ref().unwrap()["incoming_edges"].as_array().unwrap().len(), 2);
        assert!(manager.get_resolved().is_empty());
    }

    #[test]
    fn locked_resolution_rejects_duplicate_coordinate_nodes_and_discards_the_partial_graph() {
        let temp = tempdir().unwrap();
        let root = temp.path();
        for (path, version) in [("deps/first", "1.0.0"), ("deps/second", "2.0.0")] {
            write_path_package(root, path, "shared", version);
            let manifest_path = root.join(path).join("Cell.toml");
            let manifest = std::fs::read_to_string(&manifest_path)
                .unwrap()
                .replace(&format!("version = \"{version}\""), &format!("version = \"{version}\"\nnamespace = \"cellscript\""));
            std::fs::write(manifest_path, manifest).unwrap();
        }
        std::fs::write(
            root.join("Cell.toml"),
            r#"
[package]
edition = "2026"
name = "app"
version = "1.0.0"

[dependencies.first]
package = "shared"
path = "deps/first"

[dependencies.second]
package = "shared"
path = "deps/second"
"#,
        )
        .unwrap();

        let mut lockfile = Lockfile::new();
        lockfile.package = LockfilePackageInfo {
            edition: CURRENT_EDITION,
            name: "app".to_string(),
            version: "1.0.0".to_string(),
            namespace: None,
            source_hash: Some(registry::compute_source_hash(root).unwrap()),
            compiler_source_hash: None,
            compiler_requirement: "*".to_string(),
            resolver_compiler_version: crate::VERSION.to_string(),
        };
        lockfile.root.manifest_digest = compute_manifest_digest(root).unwrap();
        for (alias, path, version) in [("first", "deps/first", "1.0.0"), ("second", "deps/second", "2.0.0")] {
            let package_root = root.join(path);
            let manifest = std::fs::read(package_root.join("Cell.toml")).unwrap();
            let package = ResolvedPackage {
                node_id: String::new(),
                name: "shared".to_string(),
                version: version.to_string(),
                path: package_root.clone(),
                source: PackageSource::Local(PathBuf::from(path)),
                dependencies: BTreeMap::new(),
                namespace: Some("cellscript".to_string()),
                source_hash: Some(registry::compute_source_hash(&package_root).unwrap()),
                manifest_digest: manifest_digest(&manifest),
                compiler_requirement: "*".to_string(),
            };
            let node_id = package_node_id(&package, &ResolutionOptions::default(), None);
            lockfile.root.dependencies.insert(alias.to_string(), node_id.clone());
            lockfile.dependencies.insert(
                node_id,
                LockedDependency {
                    name: package.name,
                    namespace: package.namespace,
                    version: package.version,
                    source: LockedSource::Path { path: path.to_string() },
                    source_hash: package.source_hash,
                    manifest_digest: package.manifest_digest,
                    compiler_requirement: package.compiler_requirement,
                    resolver_compiler_version: crate::VERSION.to_string(),
                    dependencies: BTreeMap::new(),
                    build: None,
                },
            );
        }
        lockfile.write_to_root(root).unwrap();

        let mut manager = PackageManager::new(root);
        let error = manager.resolve_locked_dependencies(&ResolutionOptions::default()).unwrap_err();
        assert_eq!(error.code.as_deref(), Some("E2601"));
        assert_eq!(error.details.as_ref().unwrap()["conflict_kind"], "source");
        assert_eq!(error.details.as_ref().unwrap()["locked"], true);
        assert!(manager.get_resolved().is_empty());
        assert!(manager.root_dependencies().is_empty());
    }

    #[test]
    fn package_coordinates_keep_namespaces_distinct() {
        let temp = tempdir().unwrap();
        let root = temp.path();
        for (path, namespace) in [("deps/alpha", "alpha"), ("deps/beta", "beta")] {
            write_path_package(root, path, "shared", "1.0.0");
            let manifest_path = root.join(path).join("Cell.toml");
            let manifest = std::fs::read_to_string(&manifest_path)
                .unwrap()
                .replace("version = \"1.0.0\"", &format!("version = \"1.0.0\"\nnamespace = \"{namespace}\""));
            std::fs::write(manifest_path, manifest).unwrap();
        }
        std::fs::write(
            root.join("Cell.toml"),
            r#"
[package]
edition = "2026"
name = "app"
version = "1.0.0"

[dependencies.alpha]
package = "shared"
path = "deps/alpha"

[dependencies.beta]
package = "shared"
path = "deps/beta"
"#,
        )
        .unwrap();
        let mut manager = PackageManager::new(root);
        manager.resolve_dependencies().unwrap();
        assert_ne!(manager.root_dependencies()["alpha"], manager.root_dependencies()["beta"]);
        assert_eq!(manager.get_resolved().values().filter(|package| package.name == "shared").count(), 2);
    }

    #[test]
    fn path_and_git_cannot_substitute_for_a_registry_coordinate_implicitly() {
        let temp = tempdir().unwrap();
        let registry_package = ResolvedPackage {
            node_id: String::new(),
            name: "token".to_string(),
            version: "1.0.0".to_string(),
            path: temp.path().join("registry"),
            source: PackageSource::Registry {
                registry: "https://registry.example".to_string(),
                url: "https://registry.example/token.snapshot".to_string(),
                revision: format!("sha256:{}", "11".repeat(32)),
                namespace: "cellscript".to_string(),
                version: "1.0.0".to_string(),
            },
            dependencies: BTreeMap::new(),
            namespace: Some("cellscript".to_string()),
            source_hash: Some("registry-hash".to_string()),
            manifest_digest: "registry-manifest".to_string(),
            compiler_requirement: "*".to_string(),
        };
        let dependency = Dependency::Simple("1.0.0".to_string());
        for alternate_source in [
            PackageSource::Local(PathBuf::from("deps/token")),
            PackageSource::Git { url: "https://git.example/token".to_string(), revision: "22".repeat(20) },
        ] {
            let alternate = ResolvedPackage {
                source: alternate_source,
                path: temp.path().join("alternate"),
                source_hash: Some("alternate-hash".to_string()),
                manifest_digest: "alternate-manifest".to_string(),
                ..registry_package.clone()
            };
            let mut manager = PackageManager::new(temp.path());
            let registry_node = package_node_id(&registry_package, &ResolutionOptions::default(), None);
            manager
                .register_package_instance(
                    &registry_package,
                    &registry_node,
                    &ResolutionOptions::default(),
                    None,
                    "app",
                    "published",
                    &dependency,
                    false,
                )
                .unwrap();
            let alternate_node = package_node_id(&alternate, &ResolutionOptions::default(), None);
            let error = manager
                .register_package_instance(
                    &alternate,
                    &alternate_node,
                    &ResolutionOptions::default(),
                    None,
                    "app",
                    "override",
                    &dependency,
                    false,
                )
                .unwrap_err();
            assert_eq!(error.code.as_deref(), Some("E2601"));
            assert_eq!(error.details.as_ref().unwrap()["conflict_kind"], "source");
            assert_eq!(error.details.as_ref().unwrap()["incoming_edges"].as_array().unwrap().len(), 2);
        }
    }

    #[test]
    fn feature_variants_for_one_coordinate_fail_before_source_loading() {
        let temp = tempdir().unwrap();
        let root = temp.path();
        for (path, name) in [("deps/left", "left"), ("deps/right", "right"), ("deps/shared", "shared")] {
            write_path_package(root, path, name, "1.0.0");
        }
        let shared_manifest = root.join("deps/shared/Cell.toml");
        let manifest = format!("{}\n[features]\nleft = []\nright = []\n", std::fs::read_to_string(&shared_manifest).unwrap());
        std::fs::write(shared_manifest, manifest).unwrap();
        for (parent, feature) in [("left", "left"), ("right", "right")] {
            let parent_manifest = root.join("deps").join(parent).join("Cell.toml");
            let manifest = format!(
                "{}\n[dependencies.shared]\npath = \"../shared\"\ndefault_features = false\nfeatures = [\"{feature}\"]\n",
                std::fs::read_to_string(&parent_manifest).unwrap()
            );
            std::fs::write(parent_manifest, manifest).unwrap();
        }
        std::fs::write(
            root.join("Cell.toml"),
            r#"
[package]
edition = "2026"
name = "app"
version = "1.0.0"

[dependencies.left]
path = "deps/left"

[dependencies.right]
path = "deps/right"
"#,
        )
        .unwrap();

        let mut manager = PackageManager::new(root);
        let error = manager.resolve_dependencies().unwrap_err();
        assert_eq!(error.code.as_deref(), Some("E2601"));
        assert_eq!(error.details.as_ref().unwrap()["coordinate"]["name"], "shared");
        assert_eq!(error.details.as_ref().unwrap()["conflict_kind"], "feature");
        assert_eq!(error.details.as_ref().unwrap()["incoming_edges"][0]["features"], serde_json::json!(["left"]));
        assert_eq!(error.details.as_ref().unwrap()["incoming_edges"][1]["features"], serde_json::json!(["right"]));
        assert!(manager.get_resolved().is_empty());
    }

    #[test]
    fn lockfile_binds_root_and_transitive_compiler_requirements() {
        let temp = tempdir().unwrap();
        let root = temp.path();
        write_path_package(root, "deps/math", "math", "1.2.3");
        let dependency_manifest = root.join("deps/math/Cell.toml");
        let dependency_source = std::fs::read_to_string(&dependency_manifest)
            .unwrap()
            .replace("version = \"1.2.3\"", "version = \"1.2.3\"\ncellscript_version = \">=0.16\"");
        std::fs::write(&dependency_manifest, dependency_source).unwrap();
        std::fs::write(
            root.join("Cell.toml"),
            r#"
[package]
edition = "2026"
name = "app"
version = "1.0.0"
cellscript_version = ">=0.20"

[dependencies.math]
path = "deps/math"
version = "1.2.3"
"#,
        )
        .unwrap();

        write_test_lock(root, &ResolutionOptions::default());
        let mut lockfile = Lockfile::read_from_root(root).unwrap().unwrap();
        assert_eq!(lockfile.package.compiler_requirement, ">=0.20");
        assert_eq!(lockfile.package.resolver_compiler_version, crate::VERSION);
        let node = lockfile.root.dependencies.get("math").unwrap().clone();
        assert!(node.contains("compiler=3e3d302e3136"), "{node}");
        let dependency = lockfile.dependencies.get(&node).unwrap();
        assert_eq!(dependency.compiler_requirement, ">=0.16");
        assert_eq!(dependency.resolver_compiler_version, crate::VERSION);

        lockfile.dependencies.get_mut(&node).unwrap().compiler_requirement = "*".to_string();
        lockfile.write_to_root(root).unwrap();
        let error = PackageManager::new(root).resolve_locked_dependencies(&ResolutionOptions::default()).unwrap_err();
        assert!(error.message.contains("compiler requirement '*' does not match Cell.toml '>=0.16'"), "{}", error.message);
    }

    #[test]
    fn locked_resolution_revalidates_active_compiler_without_selecting_a_replacement() {
        let temp = tempdir().unwrap();
        let root = temp.path();
        write_path_package(root, "deps/math", "math", "1.2.3");
        std::fs::write(
            root.join("Cell.toml"),
            r#"
[package]
edition = "2026"
name = "app"
version = "1.0.0"

[dependencies.math]
path = "deps/math"
version = "1.2.3"
"#,
        )
        .unwrap();
        write_test_lock(root, &ResolutionOptions::default());

        let dependency_manifest = root.join("deps/math/Cell.toml");
        let future_manifest = std::fs::read_to_string(&dependency_manifest)
            .unwrap()
            .replace("version = \"1.2.3\"", "version = \"1.2.3\"\ncellscript_version = \">=999.0.0\"");
        std::fs::write(&dependency_manifest, future_manifest).unwrap();
        std::fs::write(root.join("deps/math/src/lib.cell"), "this source must not be parsed").unwrap();

        let manager = PackageManager::new(root);
        let resolved = manager.resolve_from_path("math", "deps/math").unwrap();
        let future_node = package_node_id(&resolved, &ResolutionOptions::default(), None);
        let mut lockfile = Lockfile::read_from_root(root).unwrap().unwrap();
        let old_node = lockfile.root.dependencies.get("math").unwrap().clone();
        let mut locked = lockfile.dependencies.remove(&old_node).unwrap();
        locked.compiler_requirement = resolved.compiler_requirement.clone();
        locked.manifest_digest = resolved.manifest_digest.clone();
        locked.source_hash = resolved.source_hash.clone();
        lockfile.dependencies.insert(future_node.clone(), locked);
        lockfile.root.dependencies.insert("math".to_string(), future_node.clone());
        lockfile.write_to_root(root).unwrap();

        let error = PackageManager::new(root).resolve_locked_dependencies(&ResolutionOptions::default()).unwrap_err();
        assert_eq!(error.code.as_deref(), Some("E2600"));
        assert_eq!(error.details.as_ref().unwrap()["compiler_requirement"], ">=999.0.0");
        assert_eq!(error.details.as_ref().unwrap()["phase"], "manifest-before-source");
        assert_eq!(error.details.as_ref().unwrap()["incoming_edge"]["alias"], "math");
        assert!(error.message.contains("before loading source"), "{}", error.message);
        assert_eq!(lockfile.root.dependencies["math"], future_node);
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

    fn locked_path(name: &str, version: &str, path: &str, dependencies: BTreeMap<String, String>) -> LockedDependency {
        LockedDependency {
            name: name.to_string(),
            namespace: None,
            version: version.to_string(),
            source: LockedSource::Path { path: path.to_string() },
            source_hash: Some(format!("hash-{name}")),
            manifest_digest: format!("manifest-{name}"),
            dependencies,
            build: None,
            compiler_requirement: "*".to_string(),
            resolver_compiler_version: crate::VERSION.to_string(),
        }
    }

    fn resolved_path(name: &str, version: &str, path: &str, dependencies: BTreeMap<String, String>) -> ResolvedPackage {
        ResolvedPackage {
            node_id: name.to_string(),
            name: name.to_string(),
            version: version.to_string(),
            path: PathBuf::from(path),
            source: PackageSource::Local(PathBuf::from(path)),
            dependencies,
            namespace: None,
            source_hash: Some(format!("hash-{name}")),
            manifest_digest: format!("manifest-{name}"),
            compiler_requirement: "*".to_string(),
        }
    }

    #[test]
    fn test_version_compatibility() {
        assert!(version::satisfies("1.2.3", &VersionReq::Compatible("1.0.0".to_string())));
        assert!(version::satisfies("1.5.0", &VersionReq::Compatible("1.2.3".to_string())));
        assert!(!version::satisfies("1.1.9", &VersionReq::Compatible("1.2.3".to_string())));
        assert!(!version::satisfies("2.0.0", &VersionReq::Compatible("1.0.0".to_string())));
        assert!(!version::satisfies("0.2.0", &VersionReq::Compatible("0.1.0".to_string())));
        assert!(version::satisfies("0.1.5", &VersionReq::Compatible("0.1.0".to_string())));
        assert!(!version::satisfies("0.1.0-alpha.1", &VersionReq::Compatible("0.1.0".to_string())));
        assert!(version::satisfies("0.1.0-alpha.2", &VersionReq::Compatible("0.1.0-alpha.1".to_string())));
        assert!(version::satisfies("1.2.3+build.7", &VersionReq::Exact("1.2.3".to_string())));
        assert!(version::satisfies("1.2.3", &VersionReq::Range(">=1.0.0, <2.0.0".to_string())));
        assert!(!version::satisfies("2.0.0", &VersionReq::Range(">=1.0.0, <2.0.0".to_string())));
        assert!(!version::satisfies("1.2.3", &VersionReq::Range(">=1.3.0".to_string())));
        assert!(!version::satisfies("1.bad", &VersionReq::Compatible("1.0.0".to_string())));
        assert!(!version::satisfies("1.2.3", &VersionReq::Compatible("1.bad".to_string())));
        assert!(!version::satisfies("1.bad", &VersionReq::Range(">=1.0.0".to_string())));
        assert!(version::parse_version_req("^1.bad").is_err());
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
edition = "2026"
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
edition = "2026"
name = "math"
version = "0.1.0"
"#,
        )
        .unwrap();

        let mut manager = PackageManager::new(root);
        manager.resolve_dependencies().unwrap();

        let math_id = manager.root_dependencies().get("math").expect("root math edge");
        let math = manager.get_resolved().get(math_id).expect("path dependency should resolve");
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
edition = "2026"
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
edition = "2026"
name = "math"
version = "0.2.0"
"#,
        )
        .unwrap();

        let mut manager = PackageManager::new(root);
        manager.resolve_dependencies().unwrap();

        let math_id = manager.root_dependencies().get("math").expect("root math edge");
        let math = manager.get_resolved().get(math_id).expect("path dependency should resolve");
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
edition = "2026"
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
edition = "2026"
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
edition = "2026"
name = "util"
version = "0.1.0"
"#,
        )
        .unwrap();

        let mut manager = PackageManager::new(root);
        manager.resolve_dependencies().unwrap();

        let math_id = manager.root_dependencies().get("math").expect("root math edge");
        let math = manager.get_resolved().get(math_id).expect("math node");
        let util_id = math.dependencies.get("util").expect("math util edge");
        assert!(manager.get_resolved().contains_key(util_id));
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
edition = "2026"
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
edition = "2026"
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
edition = "2026"
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

    fn write_test_lock(root: &Path, options: &ResolutionOptions) {
        let mut manager = PackageManager::new(root);
        let manifest = manager.read_manifest().unwrap();
        manager.resolve_dependencies_with_options(options).unwrap();
        let mut lockfile = Lockfile::new();
        lockfile.package = LockfilePackageInfo {
            edition: manifest.package.edition,
            name: manifest.package.name.clone(),
            version: manifest.package.version.clone(),
            namespace: manifest.package.namespace.clone(),
            source_hash: Some(registry::compute_source_hash(root).unwrap()),
            compiler_source_hash: None,
            compiler_requirement: manifest.package.cellscript_version.clone(),
            resolver_compiler_version: crate::VERSION.to_string(),
        };
        lockfile.replace_with_resolution(&manager, &manifest, options).unwrap();
        lockfile.write_to_root(root).unwrap();
    }

    fn write_path_package(root: &Path, relative: &str, name: &str, version: &str) {
        let package = root.join(relative);
        std::fs::create_dir_all(package.join("src")).unwrap();
        std::fs::write(
            package.join("Cell.toml"),
            format!("[package]\nedition = \"2026\"\nname = \"{name}\"\nversion = \"{version}\"\n"),
        )
        .unwrap();
        std::fs::write(package.join("src/lib.cell"), format!("module {name};\n")).unwrap();
    }

    #[test]
    fn locked_resolution_requires_explicit_lock_and_detects_source_drift() {
        let temp = tempdir().unwrap();
        let root = temp.path();
        write_path_package(root, "deps/math", "math", "1.2.3");
        std::fs::write(
            root.join("Cell.toml"),
            r#"
[package]
edition = "2026"
name = "app"
version = "0.1.0"

[dependencies.math]
path = "deps/math"
version = "^1.2.0"
"#,
        )
        .unwrap();

        let mut manager = PackageManager::new(root);
        let missing = manager.resolve_locked_dependencies(&ResolutionOptions::default()).unwrap_err();
        assert!(missing.message.contains("Cell.lock is missing"), "{}", missing.message);

        write_test_lock(root, &ResolutionOptions::default());
        let mut manager = PackageManager::new(root);
        manager.resolve_locked_dependencies(&ResolutionOptions::default()).unwrap();
        std::fs::write(root.join("deps/math/src/lib.cell"), "module math;\n// changed\n").unwrap();
        let mut manager = PackageManager::new(root);
        let drift = manager.resolve_locked_dependencies(&ResolutionOptions::default()).unwrap_err();
        assert!(drift.message.contains("source hash mismatch"), "{}", drift.message);
    }

    #[cfg(unix)]
    #[test]
    fn external_resolver_is_bounded_normalized_and_absent_from_locked_builds() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempdir().unwrap();
        let root = temp.path();
        let dependency_repo = root.join("resolver-package");
        write_path_package(root, "resolver-package", "resolved_math", "1.2.3");
        for arguments in [
            vec!["init", "-q"],
            vec!["config", "user.email", "tests@cellscript.dev"],
            vec!["config", "user.name", "CellScript Tests"],
            vec!["add", "."],
            vec!["commit", "-q", "-m", "initial"],
        ] {
            let status = std::process::Command::new("git").args(arguments).current_dir(&dependency_repo).status().unwrap();
            assert!(status.success());
        }
        let revision = PackageManager::git_revision(&dependency_repo).unwrap();
        let response = serde_json::json!({
            "schema": EXTERNAL_RESOLVER_RESPONSE_SCHEMA,
            "dependency": {
                "package": "resolved_math",
                "version": "1.2.3",
                "git": dependency_repo.to_string_lossy(),
                "rev": revision,
            }
        });
        let resolver_path = root.join("resolver.sh");
        std::fs::write(&resolver_path, format!("#!/bin/sh\nprintf '%s\\n' '{}'\n", response)).unwrap();
        let mut permissions = std::fs::metadata(&resolver_path).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&resolver_path, permissions).unwrap();
        let resolver_digest = sha256_file(&resolver_path).unwrap();
        std::fs::write(
            root.join("Cell.toml"),
            format!(
                r#"
[package]
edition = "2026"
name = "app"
version = "0.1.0"

[resolvers.local]
command = "{}"
sha256 = "sha256:{}"

[dependencies.math]
package = "resolved_math"
version = "^1.2.0"
resolver = "local"
"#,
                resolver_path.display(),
                resolver_digest
            ),
        )
        .unwrap();

        write_test_lock(root, &ResolutionOptions::default());
        let lockfile = Lockfile::read_from_root(root).unwrap().unwrap();
        let target = lockfile.root.dependencies.get("math").unwrap();
        assert!(matches!(lockfile.dependencies[target].source, LockedSource::Git { .. }));

        std::fs::remove_file(&resolver_path).unwrap();
        let mut locked = PackageManager::new(root);
        locked.resolve_locked_dependencies(&ResolutionOptions::default()).unwrap();
        assert_eq!(locked.get_resolved()[target].version, "1.2.3");
    }

    #[test]
    fn moving_git_branch_changes_only_after_explicit_repin() {
        let temp = tempdir().unwrap();
        let root = temp.path();
        let dependency_repo = root.join("moving-package");
        write_path_package(root, "moving-package", "moving_math", "1.2.3");
        for arguments in [
            vec!["init", "-q", "--initial-branch=main"],
            vec!["config", "user.email", "tests@cellscript.dev"],
            vec!["config", "user.name", "CellScript Tests"],
            vec!["add", "."],
            vec!["commit", "-q", "-m", "first"],
        ] {
            let status = std::process::Command::new("git").args(arguments).current_dir(&dependency_repo).status().unwrap();
            assert!(status.success());
        }
        std::fs::write(
            root.join("Cell.toml"),
            format!(
                r#"
[package]
edition = "2026"
name = "app"
version = "0.1.0"

[dependencies.math]
package = "moving_math"
version = "^1.2.0"
git = "{}"
branch = "main"
"#,
                dependency_repo.display()
            ),
        )
        .unwrap();

        write_test_lock(root, &ResolutionOptions::default());
        let first_lock = Lockfile::read_from_root(root).unwrap().unwrap();
        let first_target = first_lock.root.dependencies.get("math").unwrap();
        let first_revision = match &first_lock.dependencies[first_target].source {
            LockedSource::Git { revision, .. } => revision.clone(),
            source => panic!("expected Git source, got {source:?}"),
        };

        std::fs::write(dependency_repo.join("src/lib.cell"), "module moving_math;\n// second commit\n").unwrap();
        for arguments in [vec!["add", "."], vec!["commit", "-q", "-m", "second"]] {
            let status = std::process::Command::new("git").args(arguments).current_dir(&dependency_repo).status().unwrap();
            assert!(status.success());
        }
        let second_revision = PackageManager::git_revision(&dependency_repo).unwrap();
        assert_ne!(first_revision, second_revision);

        let mut locked = PackageManager::new(root);
        locked.resolve_locked_dependencies(&ResolutionOptions::default()).unwrap();
        assert!(locked.get_resolved().contains_key(first_target));

        write_test_lock(root, &ResolutionOptions::default());
        let repinned = Lockfile::read_from_root(root).unwrap().unwrap();
        let repinned_target = repinned.root.dependencies.get("math").unwrap();
        let repinned_revision = match &repinned.dependencies[repinned_target].source {
            LockedSource::Git { revision, .. } => revision,
            source => panic!("expected Git source, got {source:?}"),
        };
        assert_eq!(repinned_revision, &second_revision);
        assert_ne!(repinned_revision, &first_revision);
    }

    #[test]
    fn git_package_rejects_incompatible_compiler_before_source_loading() {
        if std::process::Command::new("git").arg("--version").output().is_err() {
            return;
        }
        let temp = tempdir().unwrap();
        let root = temp.path();
        let dependency_repo = root.join("future-git");
        write_path_package(root, "future-git", "future_git", "1.0.0");
        let manifest_path = dependency_repo.join("Cell.toml");
        let manifest = std::fs::read_to_string(&manifest_path)
            .unwrap()
            .replace("version = \"1.0.0\"", "version = \"1.0.0\"\ncellscript_version = \">=999.0.0\"");
        std::fs::write(&manifest_path, manifest).unwrap();
        std::fs::write(dependency_repo.join("src/lib.cell"), "this source must not be parsed").unwrap();
        for arguments in [
            vec!["init", "-q"],
            vec!["config", "user.email", "tests@cellscript.dev"],
            vec!["config", "user.name", "CellScript Tests"],
            vec!["add", "."],
            vec!["commit", "-q", "-m", "future compiler package"],
        ] {
            let status = std::process::Command::new("git").args(arguments).current_dir(&dependency_repo).status().unwrap();
            assert!(status.success());
        }
        std::fs::write(
            root.join("Cell.toml"),
            format!(
                r#"
[package]
edition = "2026"
name = "app"
version = "1.0.0"

[dependencies.future]
package = "future_git"
git = "{}"
"#,
                dependency_repo.display()
            ),
        )
        .unwrap();

        let error = PackageManager::new(root).resolve_dependencies().unwrap_err();

        assert_eq!(error.code.as_deref(), Some("E2600"));
        let incompatible = &error.details.as_ref().unwrap()["incompatible_packages"][0];
        assert_eq!(incompatible["package"], "future_git");
        assert_eq!(incompatible["incoming_edge"]["from_package"], "app");
        assert_eq!(incompatible["incoming_edge"]["alias"], "future");
        assert!(incompatible["message"].as_str().unwrap().contains("before loading source"));
    }

    #[test]
    fn optional_features_and_dev_dependencies_select_locked_subgraphs() {
        let temp = tempdir().unwrap();
        let root = temp.path();
        write_path_package(root, "deps/base", "base", "1.0.0");
        write_path_package(root, "deps/extra", "extra", "1.0.0");
        write_path_package(root, "deps/test-kit", "test-kit", "1.0.0");
        std::fs::write(
            root.join("Cell.toml"),
            r#"
[package]
edition = "2026"
name = "app"
version = "0.1.0"

[dependencies.base]
path = "deps/base"

[dependencies.extra]
path = "deps/extra"
optional = true

[dev_dependencies.test]
package = "test-kit"
path = "deps/test-kit"

[features]
default = []
extended = ["dep:extra"]
"#,
        )
        .unwrap();
        write_test_lock(root, &ResolutionOptions { scope: DependencyScope::Test, all_features: true, ..ResolutionOptions::default() });

        let mut runtime = PackageManager::new(root);
        runtime.resolve_locked_dependencies(&ResolutionOptions::default()).unwrap();
        assert_eq!(runtime.root_dependencies().keys().cloned().collect::<Vec<_>>(), vec!["base"]);

        let mut extended = PackageManager::new(root);
        extended
            .resolve_locked_dependencies(&ResolutionOptions {
                features: BTreeSet::from(["extended".to_string()]),
                ..ResolutionOptions::default()
            })
            .unwrap();
        assert_eq!(extended.root_dependencies().keys().cloned().collect::<Vec<_>>(), vec!["base", "extra"]);

        let mut tests = PackageManager::new(root);
        tests
            .resolve_locked_dependencies(&ResolutionOptions { scope: DependencyScope::Test, ..ResolutionOptions::default() })
            .unwrap();
        assert_eq!(tests.root_dependencies().keys().cloned().collect::<Vec<_>>(), vec!["base", "test"]);
        let test_node = tests.root_dependencies().get("test").unwrap();
        assert_eq!(tests.get_resolved()[test_node].name, "test-kit");
    }

    #[test]
    fn environment_overrides_bind_chain_identity_and_dependency_graph() {
        let temp = tempdir().unwrap();
        let root = temp.path();
        write_path_package(root, "deps/mainnet", "contracts", "1.0.0");
        write_path_package(root, "deps/testnet", "contracts", "2.0.0");
        std::fs::write(
            root.join("Cell.toml"),
            format!(
                r#"
[package]
edition = "2026"
name = "app"
version = "0.1.0"

[dependencies.contracts]
path = "deps/mainnet"

[environments.mainnet]
chain_id = "ckb-mainnet"
genesis_hash = "0x{}"

[environments.testnet]
chain_id = "ckb-testnet"
genesis_hash = "0x{}"

[dependency_overrides.testnet.contracts]
path = "deps/testnet"
"#,
                "11".repeat(32),
                "22".repeat(32)
            ),
        )
        .unwrap();

        let manifest = PackageManager::new(root).read_manifest().unwrap();
        let mut lockfile = Lockfile::new();
        lockfile.package.edition = CURRENT_EDITION;
        for environment in manifest.environments.keys() {
            let options = ResolutionOptions {
                environment: Some(environment.clone()),
                scope: DependencyScope::Test,
                all_features: true,
                ..ResolutionOptions::default()
            };
            let mut manager = PackageManager::new(root);
            manager.resolve_dependencies_with_options(&options).unwrap();
            lockfile.merge_resolution(&manager, &manifest, &options).unwrap();
        }
        lockfile.write_to_root(root).unwrap();

        let mut mainnet = PackageManager::new(root);
        mainnet
            .resolve_locked_dependencies(&ResolutionOptions {
                environment: Some("mainnet".to_string()),
                ..ResolutionOptions::default()
            })
            .unwrap();
        let mainnet_node = mainnet.root_dependencies().get("contracts").unwrap();
        assert_eq!(mainnet.get_resolved()[mainnet_node].version, "1.0.0");

        let mut testnet = PackageManager::new(root);
        testnet
            .resolve_locked_dependencies(&ResolutionOptions {
                environment: Some("testnet".to_string()),
                ..ResolutionOptions::default()
            })
            .unwrap();
        let testnet_node = testnet.root_dependencies().get("contracts").unwrap();
        assert_eq!(testnet.get_resolved()[testnet_node].version, "2.0.0");

        let missing = PackageManager::new(root).resolve_locked_dependencies(&ResolutionOptions::default()).unwrap_err();
        assert!(missing.message.contains("--environment"), "{}", missing.message);
    }

    #[test]
    fn transitive_environment_selection_uses_chain_identity_across_local_names_and_a_diamond() {
        let temp = tempdir().unwrap();
        let root = temp.path();
        for (relative, name) in [("deps/left", "left"), ("deps/right", "right"), ("deps/common", "common")] {
            write_path_package(root, relative, name, "1.0.0");
        }
        let genesis = "11".repeat(32);
        std::fs::write(
            root.join("deps/common/Cell.toml"),
            format!(
                "[package]\nedition = \"2026\"\nname = \"common\"\nversion = \"1.0.0\"\n\n[environments.live]\nchain_id = \"ckb\"\ngenesis_hash = \"0x{genesis}\"\n"
            ),
        )
        .unwrap();
        for (relative, name, local_environment) in [("deps/left", "left", "production"), ("deps/right", "right", "ckb-main")] {
            std::fs::write(
                root.join(relative).join("Cell.toml"),
                format!(
                    "[package]\nedition = \"2026\"\nname = \"{name}\"\nversion = \"1.0.0\"\n\n[dependencies.common]\npath = \"../common\"\n\n[environments.{local_environment}]\nchain_id = \"ckb\"\ngenesis_hash = \"0x{genesis}\"\n"
                ),
            )
            .unwrap();
        }
        std::fs::write(
            root.join("Cell.toml"),
            format!(
                "[package]\nedition = \"2026\"\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies.left]\npath = \"deps/left\"\nuse_environment = \"production\"\n\n[dependencies.right]\npath = \"deps/right\"\n\n[environments.mainnet]\nchain_id = \"ckb\"\ngenesis_hash = \"0x{genesis}\"\n"
            ),
        )
        .unwrap();

        let options = ResolutionOptions { environment: Some("mainnet".to_string()), ..ResolutionOptions::default() };
        let mut manager = PackageManager::new(root);
        manager.resolve_dependencies_with_options(&options).unwrap();
        let left = manager.root_dependencies()["left"].clone();
        let right = manager.root_dependencies()["right"].clone();
        let left_common = manager.get_resolved()[&left].dependencies["common"].clone();
        let right_common = manager.get_resolved()[&right].dependencies["common"].clone();
        assert_eq!(left_common, right_common);
        assert!(left.contains("explicit-local-name"), "{left}");
        assert!(right.contains("inherit-by-chain-identity"), "{right}");
        assert!(left_common.contains("inherit-by-chain-identity"), "{left_common}");

        let manifest = manager.read_manifest().unwrap();
        let mut lockfile = Lockfile::new();
        lockfile.package.edition = CURRENT_EDITION;
        lockfile.replace_with_resolution(&manager, &manifest, &options).unwrap();
        lockfile.write_to_root(root).unwrap();
        let mut locked = PackageManager::new(root);
        locked.resolve_locked_dependencies(&options).unwrap();
        assert_eq!(locked.get_resolved()[&left].dependencies["common"], left_common);
        assert_eq!(locked.get_resolved()[&right].dependencies["common"], right_common);
    }

    #[test]
    fn transitive_environment_mismatch_and_ambiguity_fail_before_overrides_apply() {
        let temp = tempdir().unwrap();
        let root = temp.path();
        for (relative, name) in [("deps/child", "child"), ("deps/base", "base"), ("deps/alternate", "base")] {
            write_path_package(root, relative, name, "1.0.0");
        }
        std::fs::write(
            root.join("deps/child/Cell.toml"),
            format!(
                "[package]\nedition = \"2026\"\nname = \"child\"\nversion = \"1.0.0\"\n\n[dependencies.base]\npath = \"../base\"\n\n[environments.mainnet]\nchain_id = \"ckb\"\ngenesis_hash = \"0x{}\"\n\n[dependency_overrides.mainnet.base]\npath = \"../alternate\"\n",
                "22".repeat(32)
            ),
        )
        .unwrap();
        std::fs::write(
            root.join("Cell.toml"),
            format!(
                "[package]\nedition = \"2026\"\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies.child]\npath = \"deps/child\"\n\n[environments.mainnet]\nchain_id = \"ckb\"\ngenesis_hash = \"0x{}\"\n",
                "11".repeat(32)
            ),
        )
        .unwrap();
        let options = ResolutionOptions { environment: Some("mainnet".to_string()), ..ResolutionOptions::default() };
        let mismatch = PackageManager::new(root).resolve_dependencies_with_options(&options).unwrap_err();
        assert!(mismatch.message.contains("no environment matches root chain identity"), "{}", mismatch.message);

        std::fs::write(
            root.join("deps/child/Cell.toml"),
            format!(
                "[package]\nedition = \"2026\"\nname = \"child\"\nversion = \"1.0.0\"\n\n[dependencies.base]\npath = \"../base\"\n\n[environments.mainnet]\nchain_id = \"ckb-fork\"\ngenesis_hash = \"0x{}\"\n\n[dependency_overrides.mainnet.base]\npath = \"../alternate\"\n",
                "11".repeat(32)
            ),
        )
        .unwrap();
        let wrong_chain = PackageManager::new(root).resolve_dependencies_with_options(&options).unwrap_err();
        assert!(wrong_chain.message.contains("no environment matches root chain identity"), "{}", wrong_chain.message);

        std::fs::write(
            root.join("deps/child/Cell.toml"),
            format!(
                "[package]\nedition = \"2026\"\nname = \"child\"\nversion = \"1.0.0\"\n\n[environments.one]\nchain_id = \"ckb\"\ngenesis_hash = \"0x{0}\"\n\n[environments.two]\nchain_id = \"ckb\"\ngenesis_hash = \"0x{0}\"\n",
                "11".repeat(32)
            ),
        )
        .unwrap();
        let ambiguous = PackageManager::new(root).resolve_dependencies_with_options(&options).unwrap_err();
        assert!(ambiguous.message.contains("multiple environments matching root chain identity"), "{}", ambiguous.message);
    }

    #[test]
    fn explicit_environment_independence_skips_foreign_overrides_but_preserves_the_root_identity() {
        let temp = tempdir().unwrap();
        let root = temp.path();
        write_path_package(root, "deps/child", "child", "1.0.0");
        write_path_package(root, "deps/base", "base", "1.0.0");
        write_path_package(root, "deps/alternate", "base", "2.0.0");
        std::fs::write(
            root.join("deps/child/Cell.toml"),
            format!(
                "[package]\nedition = \"2026\"\nname = \"child\"\nversion = \"1.0.0\"\n\n[dependencies.base]\npath = \"../base\"\n\n[environments.foreign]\nchain_id = \"ckb-fork\"\ngenesis_hash = \"0x{}\"\n\n[dependency_overrides.foreign.base]\npath = \"../alternate\"\n",
                "22".repeat(32)
            ),
        )
        .unwrap();
        std::fs::write(
            root.join("Cell.toml"),
            format!(
                "[package]\nedition = \"2026\"\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies.child]\npath = \"deps/child\"\nenvironment_independent = true\n\n[environments.mainnet]\nchain_id = \"ckb\"\ngenesis_hash = \"0x{}\"\n",
                "11".repeat(32)
            ),
        )
        .unwrap();
        let options = ResolutionOptions { environment: Some("mainnet".to_string()), ..ResolutionOptions::default() };
        let mut manager = PackageManager::new(root);
        manager.resolve_dependencies_with_options(&options).unwrap();
        let child = &manager.get_resolved()[&manager.root_dependencies()["child"]];
        assert!(child.node_id.contains("environment-independent"), "{}", child.node_id);
        assert_eq!(manager.get_resolved()[&child.dependencies["base"]].version, "1.0.0");
    }

    #[test]
    fn locked_environment_mapping_rejects_a_rebound_dependency_manifest() {
        let temp = tempdir().unwrap();
        let root = temp.path();
        write_path_package(root, "deps/child", "child", "1.0.0");
        let genesis = "11".repeat(32);
        std::fs::write(
            root.join("deps/child/Cell.toml"),
            format!(
                "[package]\nedition = \"2026\"\nname = \"child\"\nversion = \"1.0.0\"\n\n[environments.production]\nchain_id = \"ckb\"\ngenesis_hash = \"0x{genesis}\"\n"
            ),
        )
        .unwrap();
        std::fs::write(
            root.join("Cell.toml"),
            format!(
                "[package]\nedition = \"2026\"\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies.child]\npath = \"deps/child\"\n\n[environments.mainnet]\nchain_id = \"ckb\"\ngenesis_hash = \"0x{genesis}\"\n"
            ),
        )
        .unwrap();
        let options = ResolutionOptions { environment: Some("mainnet".to_string()), ..ResolutionOptions::default() };
        write_test_lock(root, &options);
        let mut lockfile = Lockfile::read_from_root(root).unwrap().unwrap();
        let node_id = lockfile.environments["mainnet"].dependencies["child"].clone();
        std::fs::write(
            root.join("deps/child/Cell.toml"),
            format!(
                "[package]\nedition = \"2026\"\nname = \"child\"\nversion = \"1.0.0\"\n\n[environments.renamed]\nchain_id = \"ckb\"\ngenesis_hash = \"0x{genesis}\"\n"
            ),
        )
        .unwrap();
        lockfile.dependencies.get_mut(&node_id).unwrap().manifest_digest = compute_manifest_digest(&root.join("deps/child")).unwrap();
        lockfile.dependencies.get_mut(&node_id).unwrap().source_hash =
            Some(registry::compute_source_hash(&root.join("deps/child")).unwrap());
        lockfile.write_to_root(root).unwrap();

        let error = PackageManager::new(root).resolve_locked_dependencies(&options).unwrap_err();
        assert!(error.message.contains("chain-identity-safe environment selection requires"), "{}", error.message);
    }

    #[cfg(unix)]
    #[test]
    fn transitive_external_resolver_uses_validated_identity_without_inherited_name_lookup() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempdir().unwrap();
        let owner = temp.path().join("owner");
        std::fs::create_dir_all(&owner).unwrap();
        let response = serde_json::json!({
            "schema": EXTERNAL_RESOLVER_RESPONSE_SCHEMA,
            "dependency": { "package": "math", "version": "1.2.3", "namespace": "cellscript" }
        });
        let resolver_path = owner.join("resolver.sh");
        let request_path = owner.join("request.json");
        std::fs::write(&resolver_path, format!("#!/bin/sh\ncat >'{}'\nprintf '%s\\n' '{}'\n", request_path.display(), response))
            .unwrap();
        let mut permissions = std::fs::metadata(&resolver_path).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&resolver_path, permissions).unwrap();
        let digest = sha256_file(&resolver_path).unwrap();
        std::fs::write(
            owner.join("Cell.toml"),
            format!(
                "[package]\nedition = \"2026\"\nname = \"owner\"\nversion = \"1.0.0\"\n\n[resolvers.local]\ncommand = \"{}\"\nsha256 = \"sha256:{digest}\"\n\n[dependencies.math]\nversion = \"^1.2.0\"\nresolver = \"local\"\n",
                resolver_path.display()
            ),
        )
        .unwrap();
        let manifest: PackageManifest = toml::from_str(&std::fs::read_to_string(owner.join("Cell.toml")).unwrap()).unwrap();
        let Dependency::Detailed(dependency) = &manifest.dependencies["math"] else {
            panic!("expected detailed dependency");
        };
        let environment = SelectedEnvironmentContext {
            root_name: "mainnet".to_string(),
            local_name: Some("production".to_string()),
            chain_id: "ckb".to_string(),
            genesis_hash: format!("0x{}", "11".repeat(32)),
            policy: EnvironmentSelectionPolicy::InheritByChainIdentity,
        };
        let resolved = PackageManager::new(temp.path())
            .resolve_external_dependency("math", "math", dependency, &owner, &ResolutionOptions::default(), Some(&environment))
            .unwrap();
        assert_eq!(resolved.version, "=1.2.3");
        assert_eq!(resolved.namespace.as_deref(), Some("cellscript"));
        let request: serde_json::Value = serde_json::from_slice(&std::fs::read(request_path).unwrap()).unwrap();
        assert_eq!(request["schema"], EXTERNAL_RESOLVER_REQUEST_SCHEMA);
        assert_eq!(request["environment"]["root_name"], "mainnet");
        assert_eq!(request["environment"]["local_name"], "production");
        assert_eq!(request["environment"]["chain_id"], "ckb");
        assert_eq!(request["environment"]["genesis_hash"], format!("0x{}", "11".repeat(32)));
    }

    #[test]
    fn build_dependencies_fail_closed_until_isolated_execution_exists() {
        let manifest: PackageManifest = toml::from_str(
            r#"
[package]
edition = "2026"
name = "app"
version = "0.1.0"

[build.dependencies]
codegen = "1.0.0"
"#,
        )
        .unwrap();
        let temp = tempdir().unwrap();
        PackageManager::new(temp.path()).write_manifest(&manifest).unwrap();
        let error = PackageManager::new(temp.path()).resolve_dependencies().unwrap_err();
        assert!(error.message.contains("reserved"), "{}", error.message);
    }

    #[test]
    fn lockfile_consistency_reports_stale_and_mismatched_path_sources() {
        let manifest: PackageManifest = toml::from_str(
            r#"
[package]
edition = "2026"
name = "app"
version = "0.1.0"

[dependencies.math]
version = "0.1.0"
path = "deps/math"
"#,
        )
        .unwrap();
        let mut lockfile = Lockfile::new();
        lockfile.root.dependencies.insert("math".to_string(), "math-node".to_string());
        lockfile.dependencies.insert("math-node".to_string(), locked_path("math", "0.2.0", "deps/old-math", BTreeMap::new()));
        lockfile.dependencies.insert(
            "stale-node".to_string(),
            LockedDependency {
                name: "stale".to_string(),
                namespace: Some("stale".to_string()),
                version: "1.0.0".to_string(),
                source: LockedSource::Registry {
                    registry: "cellscript-registry".to_string(),
                    url: "https://github.com/example/stale".to_string(),
                    revision: "abc123".to_string(),
                    namespace: "stale".to_string(),
                    version: "1.0.0".to_string(),
                },
                source_hash: Some("hash-stale".to_string()),
                manifest_digest: "manifest-stale".to_string(),
                dependencies: BTreeMap::new(),
                build: None,
                compiler_requirement: "*".to_string(),
                resolver_compiler_version: crate::VERSION.to_string(),
            },
        );

        let issues = lockfile.consistency_issues(&manifest);

        assert!(issues.iter().any(|issue| issue.contains("expects path source 'deps/math'")), "{issues:?}");
        assert!(issues.iter().any(|issue| issue.contains("requires '0.1.0'")), "{issues:?}");
        assert!(issues.iter().any(|issue| issue.contains("unreachable dependency node 'stale-node'")), "{issues:?}");
        assert!(!lockfile.is_consistent(&manifest));
    }

    #[test]
    fn lockfile_consistency_allows_resolved_transitive_path_dependencies() {
        let manifest: PackageManifest = toml::from_str(
            r#"
[package]
edition = "2026"
name = "app"
version = "0.1.0"

[dependencies.math]
version = "0.1.0"
path = "deps/math"
"#,
        )
        .unwrap();
        let mut lockfile = Lockfile::new();
        lockfile.root.dependencies.insert("math".to_string(), "math-node".to_string());
        let math_edges = BTreeMap::from([("util".to_string(), "util-node".to_string())]);
        lockfile.dependencies.insert("math-node".to_string(), locked_path("math", "0.1.0", "deps/math", math_edges.clone()));
        lockfile.dependencies.insert("util-node".to_string(), locked_path("util", "0.1.0", "deps/math/../util", BTreeMap::new()));
        let mut resolved = BTreeMap::new();
        resolved.insert("math-node".to_string(), resolved_path("math", "0.1.0", "deps/math", math_edges));
        resolved.insert("util-node".to_string(), resolved_path("util", "0.1.0", "deps/math/../util", BTreeMap::new()));

        let issues = lockfile.consistency_issues_with_resolved(&manifest, &resolved);

        assert!(issues.is_empty(), "{issues:?}");
    }

    #[test]
    fn lockfile_replace_with_resolved_prunes_removed_dependencies() {
        let mut lockfile = Lockfile::new();
        lockfile.dependencies.insert(
            "old".to_string(),
            LockedDependency {
                name: "old".to_string(),
                namespace: Some("old".to_string()),
                version: "1.0.0".to_string(),
                source: LockedSource::Registry {
                    registry: "cellscript-registry".to_string(),
                    url: "https://github.com/example/old".to_string(),
                    revision: "def456".to_string(),
                    namespace: "old".to_string(),
                    version: "1.0.0".to_string(),
                },
                source_hash: Some("hash-old".to_string()),
                manifest_digest: "manifest-old".to_string(),
                dependencies: BTreeMap::new(),
                build: None,
                compiler_requirement: "*".to_string(),
                resolver_compiler_version: crate::VERSION.to_string(),
            },
        );

        let mut resolved = BTreeMap::new();
        resolved.insert("math".to_string(), resolved_path("math", "0.1.0", "deps/math", BTreeMap::new()));

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
    fn lockfile_requires_the_single_package_coordinate_resolver_model() {
        let mut lockfile = Lockfile::new();
        assert_eq!(lockfile.version, 5);
        assert_eq!(lockfile.resolver_model, Lockfile::CURRENT_RESOLVER_MODEL);

        lockfile.resolver_model = "multi-package-coordinate-v1".to_string();
        let error = lockfile.validate_schema().unwrap_err();
        assert_eq!(error.code.as_deref(), Some("E2601"));
        assert!(error.message.contains("unsupported Cell.lock resolver model"), "{}", error.message);
    }

    #[test]
    fn lockfile_requires_package_and_build_profile_identity() {
        let missing_package = toml::from_str::<Lockfile>(
            r#"
version = 3
schema = "cellscript-lock-v0.24-graph-v1"
resolver_model = "legacy"

[root]

[dependencies]
"#,
        )
        .unwrap_err();
        assert!(missing_package.to_string().contains("missing field `package`"));

        let missing_profile = toml::from_str::<Lockfile>(
            r#"
version = 3
schema = "cellscript-lock-v0.24-graph-v1"
resolver_model = "legacy"

[package]
edition = "2026"

[root]

[package_build]
edition = "2026"

[dependencies]
"#,
        )
        .unwrap_err();
        assert!(missing_profile.to_string().contains("missing field `compatibility_profile_hash`"));
    }

    #[test]
    fn package_manager_rejects_registry_dependencies_fail_closed() {
        let temp = tempdir().unwrap();
        std::fs::write(
            temp.path().join("Cell.toml"),
            r#"
[package]
edition = "2026"
name = "app"
version = "0.1.0"

[dependencies]
remote = "1.2.3"
"#,
        )
        .unwrap();

        let mut manager = PackageManager::new(temp.path());
        let error = manager.resolve_dependencies().unwrap_err();

        // Registry dependencies require a namespace — without one, fail closed
        assert!(error.message.contains("namespace") || error.message.contains("registry"), "{}", error.message);
        assert!(manager.get_resolved().is_empty());
    }

    #[test]
    fn package_manager_git_dependency_fails_for_invalid_url() {
        let temp = tempdir().unwrap();
        std::fs::write(
            temp.path().join("Cell.toml"),
            r#"
[package]
edition = "2026"
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

    #[test]
    fn deployed_manifest_round_trip() {
        let manifest = DeployedManifest {
            version: DeployedManifest::CURRENT_VERSION,
            schema: DEPLOYED_MANIFEST_SCHEMA.to_string(),
            package: DeployedPackageInfo {
                edition: CURRENT_EDITION,
                name: "amm_pool".to_string(),
                version: "1.2.0".to_string(),
                source_hash: Some("blake2b:0xabcd".to_string()),
            },
            build: Some(DeployedBuildInfo {
                edition: CURRENT_EDITION,
                compatibility_profile_hash: "test-compatibility-profile".to_string(),
                compiler_version: Some("0.19.0".to_string()),
                artifact_hash: Some("blake2b:0x1234".to_string()),
                metadata_hash: None,
                schema_hash: None,
                cell_data_codec_manifest_hash: None,
                abi_hash: None,
                constraints_hash: None,
            }),
            deployments: vec![DeploymentRecord {
                edition: CURRENT_EDITION,
                compatibility_profile_hash: "test-compatibility-profile".to_string(),
                network: "aggron4".to_string(),
                chain_id: "ckb-testnet".to_string(),
                tx_hash: "0xaaaa".to_string(),
                output_index: 0,
                code_hash: "0xbbbb".to_string(),
                hash_type: "data1".to_string(),
                dep_type: "code".to_string(),
                data_hash: "0xcccc".to_string(),
                out_point: "0xaaaa:0".to_string(),
                artifact_hash: None,
                metadata_hash: None,
                schema_hash: None,
                cell_data_codec_manifest_hash: None,
                abi_hash: None,
                constraints_hash: None,
                compiler_version: None,
                type_id: Some("0xdddd".to_string()),
                script_role: Some(ScriptRole::Type),
                status: Some(DeploymentStatus::Candidate),
                upgrade_lineage: None,
                audit_report_hash: None,
                publisher_signature: None,
                cell_deps: vec![DeploymentCellDep {
                    name: Some("secp256k1".to_string()),
                    tx_hash: "0xeeee".to_string(),
                    output_index: 1,
                    dep_type: "dep_group".to_string(),
                    hash_type: Some("type".to_string()),
                    data_hash: None,
                    type_id: None,
                }],
            }],
        };

        let toml_str = toml::to_string_pretty(&manifest).unwrap();
        assert!(toml_str.contains("network = \"aggron4\""));
        assert!(toml_str.contains("code_hash = \"0xbbbb\""));

        let parsed: DeployedManifest = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.version, DeployedManifest::CURRENT_VERSION);
        assert_eq!(parsed.package.name, "amm_pool");
        assert_eq!(parsed.deployments.len(), 1);
        assert_eq!(parsed.deployments[0].network, "aggron4");
        assert_eq!(parsed.deployments[0].cell_deps.len(), 1);
    }

    #[test]
    fn deployed_manifest_rejects_legacy_identity() {
        let toml_str = r#"
version = 1

[package]
edition = "2026"
name = "token"
version = "0.3.0"

[[deployments]]
network = "ckb-mainnet"
chain_id = "ckb-mainnet"
tx_hash = "0x1111"
output_index = 0
code_hash = "0x2222"
hash_type = "type"
dep_type = "code"
data_hash = "0x3333"
        out_point = "0x1111:0"
"#;
        let error = toml::from_str::<DeployedManifest>(toml_str).unwrap_err();
        assert!(error.to_string().contains("missing field"));
    }

    #[test]
    fn deployed_manifest_requires_profile_identity() {
        let toml_str = r#"
version = 2
schema = "cellscript-deployed-v0.23-edition-2026"

[package]
edition = "2026"
name = "token"
version = "0.3.0"

[[deployments]]
edition = "2026"
network = "ckb-mainnet"
chain_id = "ckb-mainnet"
tx_hash = "0x1111"
output_index = 0
code_hash = "0x2222"
hash_type = "type"
dep_type = "code"
data_hash = "0x3333"
out_point = "0x1111:0"
"#;
        let error = toml::from_str::<DeployedManifest>(toml_str).unwrap_err();
        assert!(error.to_string().contains("missing field `compatibility_profile_hash`"));
    }
}
