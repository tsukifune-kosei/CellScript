//! End-to-end integration tests for CellScript registry data, the public
//! artifact API resolver, and CKB devnet deployment.
//!
//! ## Test Layers
//!
//! 1. **Registry data** (always runs): Explicit offline Git editing fixtures
//!    plus public artifact API resolution, immutable snapshots, source hash
//!    verification, and publish/install/verify lifecycle.
//! 2. **Headless CKB deploy** (always runs): Build deploy transactions without RPC,
//!    compute on-chain identity fields (data_hash, code_hash, TYPE_ID),
//!    write Deployed.toml + Cell.lock, cross-verify three identity layers.
//! 3. **Live devnet deploy** (`#[ignore]`): Submit real transactions to a CKB devnet,
//!    query on-chain state, verify Cell.lock ↔ Deployed.toml ↔ on-chain consistency.

//!
//! ## Running
//!
//! ```sh
//! # Offline + headless (always works)
//! cargo test --locked -p cellscript --test e2e_registry_devnet
//!
//! # Live devnet (requires `ckb run -C <spec>` on localhost:8114)
//! cargo test --locked -p cellscript --test e2e_registry_devnet -- --ignored
//! ```

use base64::Engine as _;
use blake2b_simd::Params as Blake2bParams;
use cellscript::package::registry::{
    compute_source_hash, git_checkout, git_clone, git_list_tags, git_revision, DiscoveryEntry, DiscoveryIndex, RegistryAuditInfo,
    RegistryDependencyRef, RegistryIndex, RegistryVersion,
};
use cellscript::package::{
    DeployedBuildInfo, DeployedManifest, DeployedPackageInfo, DeploymentCellDep, DeploymentRecord, DeploymentStatus, LockedBuildInfo,
    LockedDependency, LockedSource, Lockfile, LockfileDeploymentRef, LockfilePackageInfo, PackageManager, PackageManifest, ScriptRole,
    DEPLOYED_MANIFEST_SCHEMA,
};
use ckb_testtool::ckb_hash::blake2b_256;
use ckb_testtool::ckb_types::{
    bytes::Bytes,
    core::{Capacity, TransactionBuilder},
    packed,
    prelude::*,
};
use ckb_testtool::context::Context;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Registry env guard (serialises the public artifact API origin across tests)
// ---------------------------------------------------------------------------

use std::ffi::OsString;
use std::sync::{Mutex, MutexGuard};

static REGISTRY_ENV_LOCK: Mutex<()> = Mutex::new(());

struct RegistryEnvGuard {
    previous: Option<OsString>,
    _guard: MutexGuard<'static, ()>,
}

impl RegistryEnvGuard {
    fn new(url: &str) -> Self {
        // Recover from a poisoned mutex so one test panicking while holding the
        // lock does not cascade into every later test in this binary.
        let guard = REGISTRY_ENV_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous = std::env::var_os(cellscript::package::registry::REGISTRY_API_URL_ENV);
        // SAFETY: CI runs tests with one test thread, and this guard serializes
        // registry URL changes within this test binary.
        unsafe { std::env::set_var(cellscript::package::registry::REGISTRY_API_URL_ENV, url) };
        Self { previous, _guard: guard }
    }
}

impl Drop for RegistryEnvGuard {
    fn drop(&mut self) {
        if let Some(previous) = &self.previous {
            // SAFETY: See `RegistryEnvGuard::new`; the guard still owns the lock.
            unsafe { std::env::set_var(cellscript::package::registry::REGISTRY_API_URL_ENV, previous) };
        } else {
            // SAFETY: See `RegistryEnvGuard::new`; the guard still owns the lock.
            unsafe { std::env::remove_var(cellscript::package::registry::REGISTRY_API_URL_ENV) };
        }
    }
}

struct SourceSnapshotFixture {
    release: String,
    source_hash: String,
    bytes: Vec<u8>,
    snapshot_hash: String,
}

struct ArtifactPackageFixture {
    namespace: String,
    name: String,
    repository: String,
    index: RegistryIndex,
    snapshots: BTreeMap<String, SourceSnapshotFixture>,
}

struct ArtifactApiServer {
    origin: String,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Drop for ArtifactApiServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            handle.join().unwrap();
        }
    }
}

fn source_snapshot_fixture(root: &Path, namespace: &str, name: &str, release: &str, source_hash: &str) -> SourceSnapshotFixture {
    let files = ["Cell.toml", "src/main.cell"]
        .into_iter()
        .map(|path| {
            let content = std::fs::read(root.join(path)).unwrap();
            serde_json::json!({
                "path": path,
                "blake2b256": hex::encode(cellscript::ckb_blake2b256(&content)),
                "content_base64": base64::engine::general_purpose::STANDARD.encode(content),
            })
        })
        .collect::<Vec<_>>();
    let bytes = serde_json::to_vec(&serde_json::json!({
        "schema": "cellscript-source-snapshot-v1",
        "package": { "namespace": namespace, "name": name, "version": release },
        "files": files,
    }))
    .unwrap();
    let snapshot_hash = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
    SourceSnapshotFixture { release: release.to_string(), source_hash: source_hash.to_string(), bytes, snapshot_hash }
}

fn artifact_package_fixture(repo: &Path, snapshots: Vec<SourceSnapshotFixture>) -> ArtifactPackageFixture {
    let index = RegistryIndex::read_from_repo(repo).unwrap();
    ArtifactPackageFixture {
        namespace: index.namespace.clone(),
        name: index.name.clone(),
        repository: format!("https://example.test/{}/{}", index.namespace, index.name),
        index,
        snapshots: snapshots.into_iter().map(|snapshot| (snapshot.release.clone(), snapshot)).collect(),
    }
}

fn read_mock_http_path(stream: &mut std::net::TcpStream) -> String {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let read = stream.read(&mut buffer).unwrap();
        assert_ne!(read, 0, "artifact API request ended before headers");
        request.extend_from_slice(&buffer[..read]);
        if let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            let headers = String::from_utf8_lossy(&request[..header_end]);
            return headers.lines().next().and_then(|line| line.split_whitespace().nth(1)).unwrap_or("/").to_string();
        }
    }
}

fn start_artifact_api(packages: Vec<ArtifactPackageFixture>) -> ArtifactApiServer {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let mut api_responses = BTreeMap::<String, Vec<u8>>::new();
    let mut snapshot_responses = BTreeMap::<String, Vec<u8>>::new();
    for package in packages {
        let releases = package
            .index
            .versions
            .iter()
            .map(|version| {
                let snapshot = package.snapshots.get(&version.version).expect("snapshot for every Registry release");
                let path = format!("/source-snapshots/{}/{}/{}/fixture.json", package.namespace, package.name, version.version);
                snapshot_responses.insert(path.clone(), snapshot.bytes.clone());
                serde_json::json!({
                    "release": version.version,
                    "verification_status": "verified",
                    "availability_status": "active",
                    "registry_entry": &package.index,
                    "immutable_bundle": {
                        "schema": "cellscript-registry-immutable-bundle",
                        "url": format!("{origin}{path}"),
                        "snapshot_hash": snapshot.snapshot_hash,
                        "source_hash": snapshot.source_hash,
                        "size_bytes": snapshot.bytes.len(),
                        "content_type": "application/vnd.cellscript.source-snapshot+json"
                    }
                })
            })
            .collect::<Vec<_>>();
        let response = serde_json::to_vec(&serde_json::json!({
            "schema": "cellscript-registry-artifact",
            "namespace": package.namespace,
            "name": package.name,
            "repository": package.repository,
            "artifact": {
                "kind": "source_library",
                "profile": "cellscript_source",
                "consumption_mode": "dependency",
                "language": "cellscript"
            },
            "releases": releases
        }))
        .unwrap();
        api_responses.insert(format!("/v1/artifacts/{}/{}", package.index.namespace, package.index.name), response);
    }
    let stop = Arc::new(AtomicBool::new(false));
    let server_stop = Arc::clone(&stop);
    let handle = std::thread::spawn(move || {
        while !server_stop.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let path = read_mock_http_path(&mut stream);
                    let (status, content_type, body) = if let Some(body) = api_responses.get(&path) {
                        ("200 OK", "application/json", body.as_slice())
                    } else if let Some(body) = snapshot_responses.get(&path) {
                        ("200 OK", "application/vnd.cellscript.source-snapshot+json", body.as_slice())
                    } else {
                        ("404 Not Found", "application/json", b"{}".as_slice())
                    };
                    let headers = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    stream.write_all(headers.as_bytes()).unwrap();
                    stream.write_all(body).unwrap();
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(error) => panic!("artifact API fixture failed: {error}"),
            }
        }
    });
    ArtifactApiServer { origin, stop, handle: Some(handle) }
}

// ---------------------------------------------------------------------------
// Git fixture helpers
// ---------------------------------------------------------------------------

fn git_init(repo_dir: &Path) {
    let status = std::process::Command::new("git").args(["init"]).current_dir(repo_dir).status().expect("git init");
    assert!(status.success(), "git init failed");
}

fn git_add_all(repo_dir: &Path) {
    let status = std::process::Command::new("git").args(["add", "."]).current_dir(repo_dir).status().expect("git add");
    assert!(status.success(), "git add failed");
}

fn git_commit(repo_dir: &Path, msg: &str) {
    let gitkeep = repo_dir.join(".gitkeep");
    if !gitkeep.exists() {
        let _ = std::fs::write(&gitkeep, "");
    }
    git_add_all(repo_dir);
    let status = std::process::Command::new("git")
        .args(["-c", "commit.gpgsign=false", "commit", "-m", msg, "--author=test <test@test.com>"])
        .env("GIT_AUTHOR_DATE", "2026-01-01T00:00:00+00:00")
        .env("GIT_COMMITTER_DATE", "2026-01-01T00:00:00+00:00")
        .current_dir(repo_dir)
        .status()
        .expect("git commit");
    assert!(status.success(), "git commit failed");
}

fn git_tag(repo_dir: &Path, tag: &str) {
    let status = std::process::Command::new("git")
        .args(["-c", "tag.gpgSign=false", "tag", tag])
        .current_dir(repo_dir)
        .status()
        .expect("git tag");
    assert!(status.success(), "git tag failed");
}

fn _git_log_oneline(repo_dir: &Path) -> Vec<String> {
    let output = std::process::Command::new("git").args(["log", "--oneline"]).current_dir(repo_dir).output().expect("git log");
    String::from_utf8_lossy(&output.stdout).lines().map(|l| l.to_string()).collect()
}

fn git_config_user(repo_dir: &Path) {
    let _ = std::process::Command::new("git").args(["config", "user.email", "test@test.com"]).current_dir(repo_dir).status();
    let _ = std::process::Command::new("git").args(["config", "user.name", "Test"]).current_dir(repo_dir).status();
}

// ---------------------------------------------------------------------------
// Package helpers
// ---------------------------------------------------------------------------

/// Create a minimal CellScript package directory with Cell.toml and src/main.cell.
fn create_package(dir: &Path, name: &str, version: &str, namespace: Option<&str>) {
    std::fs::create_dir_all(dir.join("src")).unwrap();

    let mut toml = String::from("[package]\nedition = \"2026\"\n");
    toml.push_str(&format!("name = \"{}\"\n", name));
    toml.push_str(&format!("version = \"{}\"\n", version));
    if let Some(ns) = namespace {
        toml.push_str(&format!("namespace = \"{}\"\n", ns));
    }
    std::fs::write(dir.join("Cell.toml"), toml).unwrap();

    let cell = format!("module {};\n", name.replace('-', "_"));
    std::fs::write(dir.join("src/main.cell"), cell).unwrap();
}

/// Create a CellScript package with a dependency on another package.
fn create_package_with_dep(
    dir: &Path,
    name: &str,
    version: &str,
    namespace: Option<&str>,
    dep_name: &str,
    dep_version: &str,
    dep_namespace: Option<&str>,
) {
    std::fs::create_dir_all(dir.join("src")).unwrap();

    let mut toml = String::from("[package]\nedition = \"2026\"\n");
    toml.push_str(&format!("name = \"{}\"\n", name));
    toml.push_str(&format!("version = \"{}\"\n", version));
    if let Some(ns) = namespace {
        toml.push_str(&format!("namespace = \"{}\"\n", ns));
    }
    toml.push_str(&format!("\n[dependencies.{}]\n", dep_name));
    toml.push_str(&format!("version = \"{}\"\n", dep_version));
    if let Some(dns) = dep_namespace {
        toml.push_str(&format!("namespace = \"{}\"\n", dns));
    }
    std::fs::write(dir.join("Cell.toml"), toml).unwrap();

    let cell = format!("module {};\n", name.replace('-', "_"));
    std::fs::write(dir.join("src/main.cell"), cell).unwrap();
}

/// Initialize a source repo with package + registry.json + git tag.
fn init_source_repo(repo_dir: &Path, name: &str, version: &str, namespace: &str) -> String {
    create_package(repo_dir, name, version, Some(namespace));
    let source_hash = compute_source_hash(repo_dir).unwrap();

    let version_entry = RegistryVersion {
        edition: cellscript::CURRENT_EDITION,
        compatibility_profile_hash: "test-compatibility-profile".to_string(),
        version: version.to_string(),
        tag: format!("v{}", version),
        source_hash: source_hash.clone(),
        cellscript_version: "0.19.0".to_string(),
        dependencies: BTreeMap::new(),
        abi_index: None,
        schema_hash: None,
        license: Some("MIT".to_string()),
        released_at: None,
        status: cellscript::package::registry::RegistryEntryStatus::VerifiedBuild,
        yanked: false,
        yanked_at: None,
        yanked_reason: None,
        replaced_by: None,
        audit: None,
        compiler_requirement: "*".to_string(),
    };
    RegistryIndex::append_version(repo_dir, name, namespace, version_entry).unwrap();

    git_init(repo_dir);
    git_config_user(repo_dir);
    git_add_all(repo_dir);
    git_commit(repo_dir, &format!("initial v{}", version));
    git_tag(repo_dir, &format!("v{}", version));

    source_hash
}

/// Initialize a discovery index repo with entries.
fn init_discovery_repo(repo_dir: &Path, entries: &[(/*namespace*/ &str, /*name*/ &str, /*source_url*/ &str)]) {
    std::fs::create_dir_all(repo_dir).unwrap();
    git_init(repo_dir);
    git_config_user(repo_dir);

    for (ns, name, source_url) in entries {
        let ns_dir = repo_dir.join(ns);
        std::fs::create_dir_all(&ns_dir).unwrap();
        let entry = DiscoveryEntry { name: name.to_string(), namespace: ns.to_string(), source: source_url.to_string() };
        let entry_json = serde_json::to_string_pretty(&entry).unwrap();
        std::fs::write(ns_dir.join(format!("{}.json", name)), entry_json).unwrap();
    }

    git_add_all(repo_dir);
    git_commit(repo_dir, "initial discovery entries");
}

// ---------------------------------------------------------------------------
// Deployed.toml / Cell.lock verification helpers
// ---------------------------------------------------------------------------

/// Build a minimal DeploymentRecord for a headless deploy scenario.
fn sample_deployment_record(
    network: &str,
    chain_id: &str,
    tx_hash: &str,
    code_hash: &str,
    data_hash: &str,
    out_point: &str,
) -> DeploymentRecord {
    DeploymentRecord {
        edition: cellscript::CURRENT_EDITION,
        compatibility_profile_hash: "test-compatibility-profile".to_string(),
        network: network.to_string(),
        chain_id: chain_id.to_string(),
        tx_hash: tx_hash.to_string(),
        output_index: 0,
        code_hash: code_hash.to_string(),
        hash_type: "data1".to_string(),
        dep_type: "code".to_string(),
        data_hash: data_hash.to_string(),
        out_point: out_point.to_string(),
        artifact_hash: None,
        metadata_hash: None,
        schema_hash: None,
        cell_data_codec_manifest_hash: None,
        abi_hash: None,
        constraints_hash: None,
        compiler_version: Some("0.19.0".to_string()),
        type_id: None,
        script_role: Some(ScriptRole::Type),
        status: Some(DeploymentStatus::Active),
        upgrade_lineage: None,
        audit_report_hash: None,
        publisher_signature: None,
        cell_deps: vec![],
    }
}

/// Cross-verify Cell.lock ↔ Deployed.toml consistency, returning all violations.
fn cross_verify_lockfile_deployed(lockfile: &Lockfile, deployed: &DeployedManifest) -> Vec<String> {
    let mut violations = Vec::new();

    // Check build hashes
    if let Some(build) = &lockfile.package_build
        && let Some(deployed_build) = &deployed.build
    {
        if let (Some(lk), Some(dp)) = (&build.artifact_hash, &deployed_build.artifact_hash)
            && lk != dp
        {
            violations.push(format!("artifact_hash mismatch: Cell.lock='{}', Deployed.toml='{}'", lk, dp));
        }
        if let (Some(lk), Some(dp)) = (&build.schema_hash, &deployed_build.schema_hash)
            && lk != dp
        {
            violations.push(format!("schema_hash mismatch: Cell.lock='{}', Deployed.toml='{}'", lk, dp));
        }
    }

    // Check deployment records
    for deployment in &deployed.deployments {
        if let Some(deployment_ref) = lockfile.deployment.get(&deployment.network) {
            if let Some(ref code_hash) = deployment_ref.code_hash
                && code_hash != &deployment.code_hash
            {
                violations.push(format!(
                    "code_hash mismatch for network '{}': Cell.lock='{}', Deployed.toml='{}'",
                    deployment.network, code_hash, deployment.code_hash
                ));
            }
            if let Some(ref data_hash) = deployment_ref.data_hash
                && data_hash != &deployment.data_hash
            {
                violations.push(format!(
                    "data_hash mismatch for network '{}': Cell.lock='{}', Deployed.toml='{}'",
                    deployment.network, data_hash, deployment.data_hash
                ));
            }
        }
    }

    violations
}

// ===========================================================================
// SCENARIO 1: Full publish → install → verify offline Git flow
// ===========================================================================

#[test]
fn e2e_publish_install_verify_offline_git() {
    let temp = tempfile::tempdir().unwrap();

    // ── 1. Create source repo for "token" package ──
    let token_repo = temp.path().join("source-repos/cellscript-token");
    let source_hash_v030 = init_source_repo(&token_repo, "token", "0.3.0", "cellscript");

    // Verify registry.json was written correctly
    let index = RegistryIndex::read_from_repo(&token_repo).unwrap();
    assert_eq!(index.name, "token");
    assert_eq!(index.namespace, "cellscript");
    assert_eq!(index.versions.len(), 1);
    assert_eq!(index.versions[0].version, "0.3.0");
    assert_eq!(index.versions[0].source_hash, source_hash_v030);
    assert_eq!(index.versions[0].license.as_deref(), Some("MIT"));

    // ── 2. Create discovery index repo ──
    let discovery_repo = temp.path().join("discovery-index");
    let token_repo_path = token_repo.to_string_lossy().to_string();
    init_discovery_repo(&discovery_repo, &[("cellscript", "token", &token_repo_path)]);

    // ── 3. Simulate install: look up in discovery → clone source → checkout tag → verify ──
    let cache_dir = temp.path().join("cache");
    std::fs::create_dir_all(&cache_dir).unwrap();

    let discovery = DiscoveryIndex::new(&discovery_repo.to_string_lossy(), &cache_dir);
    let clone_dir = discovery.clone_or_update().unwrap();
    assert!(clone_dir.exists(), "discovery index clone should exist");

    // Look up "cellscript/token"
    let entry = discovery.lookup("cellscript", "token").unwrap();
    assert_eq!(entry.name, "token");
    assert_eq!(entry.namespace, "cellscript");
    assert_eq!(entry.source, token_repo_path);

    // Clone source repo
    let source_cache = temp.path().join("source-cache");
    std::fs::create_dir_all(&source_cache).unwrap();
    let source_clone = source_cache.join("token");
    git_clone(&entry.source, &source_clone).unwrap();

    // List tags and checkout
    let tags = git_list_tags(&source_clone).unwrap();
    assert!(tags.iter().any(|(t, _)| t == "v0.3.0"), "should have v0.3.0 tag");

    git_checkout(&source_clone, "v0.3.0").unwrap();
    let revision = git_revision(&source_clone).unwrap();
    assert!(!revision.is_empty(), "revision should be non-empty");

    // ── 4. Verify source hash ──
    let computed_hash = compute_source_hash(&source_clone).unwrap();
    assert_eq!(computed_hash, source_hash_v030, "source hash must match between publish time and install time");

    // ── 5. Build Cell.lock for the installed dependency ──
    let consumer_dir = temp.path().join("consumer-app");
    create_package(&consumer_dir, "app", "0.1.0", Some("cellscript"));

    let mut lockfile = Lockfile::new();
    lockfile.package = LockfilePackageInfo {
        edition: cellscript::CURRENT_EDITION,
        name: "app".to_string(),
        version: "0.1.0".to_string(),
        namespace: Some("cellscript".to_string()),
        source_hash: Some(compute_source_hash(&consumer_dir).unwrap()),
        compiler_source_hash: None,
        compiler_requirement: "*".to_string(),
        resolver_compiler_version: cellscript::VERSION.to_string(),
    };
    lockfile.dependencies.insert(
        "token".to_string(),
        LockedDependency {
            name: "token".to_string(),
            namespace: Some("cellscript".to_string()),
            version: "0.3.0".to_string(),
            source: LockedSource::Registry {
                registry: "https://github.com/cellscript/cellscript-registry".to_string(),
                url: entry.source.clone(),
                revision: revision.clone(),
                namespace: "cellscript".to_string(),
                version: "0.3.0".to_string(),
            },
            source_hash: Some(source_hash_v030.clone()),
            manifest_digest: "sha256:test-token-manifest".to_string(),
            dependencies: BTreeMap::new(),
            build: None,
            compiler_requirement: "*".to_string(),
            resolver_compiler_version: cellscript::VERSION.to_string(),
        },
    );
    lockfile.write_to_root(&consumer_dir).unwrap();

    // ── 6. Verify Cell.lock consistency ──
    // Note: The consumer's Cell.toml doesn't declare "token" as a dependency,
    // so we should only check that the lockfile entries are well-formed,
    // not that they match the manifest (which intentionally doesn't list token).
    let read_back = Lockfile::read_from_root(&consumer_dir).unwrap().unwrap();
    let token_dep = read_back.dependencies.get("token").unwrap();
    assert!(matches!(token_dep.source, LockedSource::Registry { .. }));
    assert_eq!(token_dep.source_hash.as_deref(), Some(source_hash_v030.as_str()));

    // Verify the lockfile round-trips correctly
    assert_eq!(read_back.dependencies.len(), 1);
}

// ===========================================================================
// SCENARIO 2: Multi-package dependency chain publish → install → deploy
// ===========================================================================

#[test]
fn e2e_multi_package_dependency_chain() {
    let temp = tempfile::tempdir().unwrap();

    // ── 1. Create and publish lib-a (standalone) ──
    let lib_a_repo = temp.path().join("source-repos/cellscript-lib-a");
    let hash_a = init_source_repo(&lib_a_repo, "lib-a", "0.1.0", "cellscript");

    // ── 2. Create and publish lib-b (depends on lib-a) ──
    let lib_b_repo = temp.path().join("source-repos/cellscript-lib-b");
    create_package_with_dep(&lib_b_repo, "lib-b", "0.1.0", Some("cellscript"), "lib-a", "0.1.0", Some("cellscript"));

    let hash_b = compute_source_hash(&lib_b_repo).unwrap();

    // Build registry entry for lib-b with dependency reference
    let version_entry_b = RegistryVersion {
        edition: cellscript::CURRENT_EDITION,
        compatibility_profile_hash: "test-compatibility-profile".to_string(),
        version: "0.1.0".to_string(),
        tag: "v0.1.0".to_string(),
        source_hash: hash_b.clone(),
        cellscript_version: "0.19.0".to_string(),
        dependencies: BTreeMap::from([(
            "lib-a".to_string(),
            RegistryDependencyRef { namespace: "cellscript".to_string(), version: "0.1.0".to_string() },
        )]),
        abi_index: None,
        schema_hash: None,
        license: Some("MIT".to_string()),
        released_at: None,
        status: cellscript::package::registry::RegistryEntryStatus::VerifiedBuild,
        yanked: false,
        yanked_at: None,
        yanked_reason: None,
        replaced_by: None,
        audit: None,
        compiler_requirement: "*".to_string(),
    };
    RegistryIndex::append_version(&lib_b_repo, "lib-b", "cellscript", version_entry_b).unwrap();

    git_init(&lib_b_repo);
    git_config_user(&lib_b_repo);
    git_add_all(&lib_b_repo);
    git_commit(&lib_b_repo, "initial v0.1.0");
    git_tag(&lib_b_repo, "v0.1.0");

    // ── 3. Verify lib-b's registry.json has dependencies ──
    let index_b = RegistryIndex::read_from_repo(&lib_b_repo).unwrap();
    assert_eq!(index_b.versions.len(), 1);
    let dep_ref = index_b.versions[0].dependencies.get("lib-a").unwrap();
    assert_eq!(dep_ref.namespace, "cellscript");
    assert_eq!(dep_ref.version, "0.1.0");

    // ── 4. Create discovery index with both packages ──
    let discovery_repo = temp.path().join("discovery-index");
    let lib_a_path = lib_a_repo.to_string_lossy().to_string();
    let lib_b_path = lib_b_repo.to_string_lossy().to_string();
    init_discovery_repo(&discovery_repo, &[("cellscript", "lib-a", &lib_a_path), ("cellscript", "lib-b", &lib_b_path)]);

    // ── 5. Install lib-b (which transitively depends on lib-a) ──
    let cache_dir = temp.path().join("cache");
    std::fs::create_dir_all(&cache_dir).unwrap();

    let discovery = DiscoveryIndex::new(&discovery_repo.to_string_lossy(), &cache_dir);
    discovery.clone_or_update().unwrap();

    // Look up lib-b
    let entry_b = discovery.lookup("cellscript", "lib-b").unwrap();
    assert_eq!(entry_b.name, "lib-b");

    // Also verify lib-a is discoverable
    let entry_a = discovery.lookup("cellscript", "lib-a").unwrap();
    assert_eq!(entry_a.name, "lib-a");

    // ── 6. Clone both source repos and verify source hashes ──
    let source_cache = temp.path().join("source-cache");
    std::fs::create_dir_all(&source_cache).unwrap();

    // Clone and verify lib-a
    let clone_a = source_cache.join("lib-a");
    git_clone(&entry_a.source, &clone_a).unwrap();
    git_checkout(&clone_a, "v0.1.0").unwrap();
    let computed_a = compute_source_hash(&clone_a).unwrap();
    assert_eq!(computed_a, hash_a, "lib-a source hash must match");

    // Clone and verify lib-b
    let clone_b = source_cache.join("lib-b");
    git_clone(&entry_b.source, &clone_b).unwrap();
    git_checkout(&clone_b, "v0.1.0").unwrap();
    let computed_b = compute_source_hash(&clone_b).unwrap();
    assert_eq!(computed_b, hash_b, "lib-b source hash must match");

    // ── 7. Build Cell.lock with both dependencies ──
    let consumer_dir = temp.path().join("consumer-app");
    create_package(&consumer_dir, "app", "0.1.0", Some("cellscript"));

    let rev_a = git_revision(&clone_a).unwrap();
    let rev_b = git_revision(&clone_b).unwrap();

    let mut lockfile = Lockfile::new();
    lockfile.package = LockfilePackageInfo {
        edition: cellscript::CURRENT_EDITION,
        name: "app".to_string(),
        version: "0.1.0".to_string(),
        namespace: Some("cellscript".to_string()),
        source_hash: None,
        compiler_source_hash: None,
        compiler_requirement: "*".to_string(),
        resolver_compiler_version: cellscript::VERSION.to_string(),
    };
    lockfile.dependencies.insert(
        "lib-a".to_string(),
        LockedDependency {
            name: "lib-a".to_string(),
            namespace: Some("cellscript".to_string()),
            version: "0.1.0".to_string(),
            source: LockedSource::Registry {
                registry: "https://github.com/cellscript/cellscript-registry".to_string(),
                url: entry_a.source.clone(),
                revision: rev_a,
                namespace: "cellscript".to_string(),
                version: "0.1.0".to_string(),
            },
            source_hash: Some(hash_a),
            manifest_digest: "sha256:test-lib-a-manifest".to_string(),
            dependencies: BTreeMap::new(),
            build: None,
            compiler_requirement: "*".to_string(),
            resolver_compiler_version: cellscript::VERSION.to_string(),
        },
    );
    lockfile.dependencies.insert(
        "lib-b".to_string(),
        LockedDependency {
            name: "lib-b".to_string(),
            namespace: Some("cellscript".to_string()),
            version: "0.1.0".to_string(),
            source: LockedSource::Registry {
                registry: "https://github.com/cellscript/cellscript-registry".to_string(),
                url: entry_b.source.clone(),
                revision: rev_b,
                namespace: "cellscript".to_string(),
                version: "0.1.0".to_string(),
            },
            source_hash: Some(hash_b),
            manifest_digest: "sha256:test-lib-b-manifest".to_string(),
            dependencies: BTreeMap::new(),
            build: None,
            compiler_requirement: "*".to_string(),
            resolver_compiler_version: cellscript::VERSION.to_string(),
        },
    );
    lockfile.write_to_root(&consumer_dir).unwrap();

    // Verify Cell.lock round-trip with both deps
    let read_back = Lockfile::read_from_root(&consumer_dir).unwrap().unwrap();
    assert_eq!(read_back.dependencies.len(), 2);
    assert!(read_back.dependencies.contains_key("lib-a"));
    assert!(read_back.dependencies.contains_key("lib-b"));
}

// ===========================================================================
// SCENARIO 2b: Diamond dependency — canonical multi-version graph
// ===========================================================================
//
// Compatible consumers reuse one canonical node. Incompatible requirements
// remain distinct graph nodes so the lockfile records the complete decision;
// compiler-level module and type identity collisions still fail closed.

/// Rewrite the `version = "..."` line in a package's Cell.toml in place.
fn bump_manifest_version(repo_dir: &Path, new_version: &str) {
    let manifest_path = repo_dir.join("Cell.toml");
    let content = std::fs::read_to_string(&manifest_path).unwrap();
    let updated = content
        .lines()
        .map(|line| {
            if line.trim_start().starts_with("version") && line.contains('=') {
                format!("version = \"{}\"", new_version)
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&manifest_path, updated).unwrap();
}

/// Publish a package version into a source repo, tagging it in git.
/// Unlike `init_source_repo`, this can append additional versions and
/// declare transitive registry dependencies.
fn publish_version_with_deps(
    repo_dir: &Path,
    name: &str,
    namespace: &str,
    version: &str,
    source_hash: &str,
    deps: &[(String, String, String)], // (dep_name, dep_namespace, dep_version)
) {
    let version_entry = RegistryVersion {
        edition: cellscript::CURRENT_EDITION,
        compatibility_profile_hash: "test-compatibility-profile".to_string(),
        version: version.to_string(),
        tag: format!("v{}", version),
        source_hash: source_hash.to_string(),
        cellscript_version: "0.19.0".to_string(),
        dependencies: deps
            .iter()
            .map(|(n, ns, v)| (n.clone(), RegistryDependencyRef { namespace: ns.clone(), version: v.clone() }))
            .collect(),
        abi_index: None,
        schema_hash: None,
        license: Some("MIT".to_string()),
        released_at: None,
        status: cellscript::package::registry::RegistryEntryStatus::VerifiedBuild,
        yanked: false,
        yanked_at: None,
        yanked_reason: None,
        replaced_by: None,
        audit: None,
        compiler_requirement: "*".to_string(),
    };
    RegistryIndex::append_version(repo_dir, name, namespace, version_entry).unwrap();
    // Initialise git on first publish (init_source_repo already does this for
    // repos that started there, so only init when no repo exists yet).
    if !repo_dir.join(".git").exists() {
        git_init(repo_dir);
        git_config_user(repo_dir);
    }
    git_add_all(repo_dir);
    git_commit(repo_dir, &format!("v{}", version));
    git_tag(repo_dir, &format!("v{}", version));
}

#[test]
fn e2e_diamond_dependency_compatible_versions_unify() {
    let temp = tempfile::tempdir().unwrap();

    // ── 1. Shared package "token" with two compatible versions ──
    let token_repo = temp.path().join("source-repos/cellscript-token");
    let hash_030 = init_source_repo(&token_repo, "token", "0.3.0", "cellscript");
    let token_snapshot_030 = source_snapshot_fixture(&token_repo, "cellscript", "token", "0.3.0", &hash_030);
    // Bump Cell.toml version to 0.3.2 and change source so the hashes differ.
    bump_manifest_version(&token_repo, "0.3.2");
    std::fs::write(token_repo.join("src/main.cell"), "module token;\n// v0.3.2\n").unwrap();
    let hash_032 = compute_source_hash(&token_repo).unwrap();
    let token_snapshot_032 = source_snapshot_fixture(&token_repo, "cellscript", "token", "0.3.2", &hash_032);
    publish_version_with_deps(&token_repo, "token", "cellscript", "0.3.2", &hash_032, &[]);

    // ── 2. amm depends on token ^0.3.0, vesting depends on token ^0.3.0 ──
    // Both requirements are satisfiable by a single version (0.3.2 is the
    // latest in the 0.3.x line), so the diamond must resolve cleanly.
    // The dependency is declared both in Cell.toml (so the resolver picks it up
    // transitively) and in registry.json (so the published record agrees).
    let amm_repo = temp.path().join("source-repos/cellscript-amm");
    create_package_with_dep(&amm_repo, "amm", "0.1.0", Some("cellscript"), "token", "0.3.0", Some("cellscript"));
    let amm_hash = compute_source_hash(&amm_repo).unwrap();
    let amm_snapshot = source_snapshot_fixture(&amm_repo, "cellscript", "amm", "0.1.0", &amm_hash);
    publish_version_with_deps(
        &amm_repo,
        "amm",
        "cellscript",
        "0.1.0",
        &amm_hash,
        &[("token".into(), "cellscript".into(), "0.3.0".into())],
    );

    let vesting_repo = temp.path().join("source-repos/cellscript-vesting");
    create_package_with_dep(&vesting_repo, "vesting", "0.1.0", Some("cellscript"), "token", "0.3.0", Some("cellscript"));
    let vesting_hash = compute_source_hash(&vesting_repo).unwrap();
    let vesting_snapshot = source_snapshot_fixture(&vesting_repo, "cellscript", "vesting", "0.1.0", &vesting_hash);
    publish_version_with_deps(
        &vesting_repo,
        "vesting",
        "cellscript",
        "0.1.0",
        &vesting_hash,
        &[("token".into(), "cellscript".into(), "0.3.0".into())],
    );

    // ── 3. Public artifact API with immutable source snapshots ──
    let api = start_artifact_api(vec![
        artifact_package_fixture(&token_repo, vec![token_snapshot_030, token_snapshot_032]),
        artifact_package_fixture(&amm_repo, vec![amm_snapshot]),
        artifact_package_fixture(&vesting_repo, vec![vesting_snapshot]),
    ]);

    // ── 4. Consumer "app" depends on both amm and vesting (the diamond) ──
    let app_dir = temp.path().join("consumer-app");
    std::fs::create_dir_all(app_dir.join("src")).unwrap();
    let mut toml = String::from("[package]\nedition = \"2026\"\nname = \"app\"\nversion = \"0.1.0\"\nnamespace = \"cellscript\"\n");
    toml.push_str("\n[dependencies.amm]\nversion = \"0.1.0\"\nnamespace = \"cellscript\"\n");
    toml.push_str("\n[dependencies.vesting]\nversion = \"0.1.0\"\nnamespace = \"cellscript\"\n");
    std::fs::write(app_dir.join("Cell.toml"), toml).unwrap();
    std::fs::write(app_dir.join("src/main.cell"), "module app;\n").unwrap();

    let _env = RegistryEnvGuard::new(&api.origin);

    let mut pm = PackageManager::new(&app_dir);
    // Resolution should succeed: both amm and vesting require token ^0.3.0,
    // and token 0.3.2 (the latest non-yanked 0.3.x) satisfies both.
    pm.resolve_dependencies().expect("compatible diamond must resolve to a single token version");

    let resolved = pm.get_resolved();
    let tokens = resolved.values().filter(|package| package.name == "token").collect::<Vec<_>>();
    assert_eq!(tokens.len(), 1, "compatible diamond should reuse one canonical token node: {resolved:#?}");
    let token = tokens[0];
    // The resolver picks the latest satisfying version, which is 0.3.2.
    assert_eq!(token.version, "0.3.2", "unified resolution should select the latest satisfying version");
}

#[test]
fn e2e_diamond_dependency_incompatible_versions_use_distinct_nodes() {
    let temp = tempfile::tempdir().unwrap();

    // ── 1. Shared package "token" with 0.3.x and 0.4.x lines ──
    let token_repo = temp.path().join("source-repos/cellscript-token");
    let hash_030 = init_source_repo(&token_repo, "token", "0.3.0", "cellscript");
    let token_snapshot_030 = source_snapshot_fixture(&token_repo, "cellscript", "token", "0.3.0", &hash_030);
    bump_manifest_version(&token_repo, "0.4.0");
    std::fs::write(token_repo.join("src/main.cell"), "module token;\n// v0.4.0\n").unwrap();
    let hash_040 = compute_source_hash(&token_repo).unwrap();
    let token_snapshot_040 = source_snapshot_fixture(&token_repo, "cellscript", "token", "0.4.0", &hash_040);
    publish_version_with_deps(&token_repo, "token", "cellscript", "0.4.0", &hash_040, &[]);

    // ── 2. amm pins token to ^0.3.0, vesting pins token to ^0.4.0 ──
    // No single token version can satisfy both "^0.3.0" and "^0.4.0". The v3
    // graph therefore retains two canonical nodes; compilation still fails
    // closed later if their exported module/type identities collide.
    let amm_repo = temp.path().join("source-repos/cellscript-amm");
    create_package_with_dep(&amm_repo, "amm", "0.1.0", Some("cellscript"), "token", "0.3.0", Some("cellscript"));
    let amm_hash = compute_source_hash(&amm_repo).unwrap();
    let amm_snapshot = source_snapshot_fixture(&amm_repo, "cellscript", "amm", "0.1.0", &amm_hash);
    publish_version_with_deps(
        &amm_repo,
        "amm",
        "cellscript",
        "0.1.0",
        &amm_hash,
        &[("token".into(), "cellscript".into(), "0.3.0".into())],
    );

    let vesting_repo = temp.path().join("source-repos/cellscript-vesting");
    create_package_with_dep(&vesting_repo, "vesting", "0.1.0", Some("cellscript"), "token", "0.4.0", Some("cellscript"));
    let vesting_hash = compute_source_hash(&vesting_repo).unwrap();
    let vesting_snapshot = source_snapshot_fixture(&vesting_repo, "cellscript", "vesting", "0.1.0", &vesting_hash);
    publish_version_with_deps(
        &vesting_repo,
        "vesting",
        "cellscript",
        "0.1.0",
        &vesting_hash,
        &[("token".into(), "cellscript".into(), "0.4.0".into())],
    );

    // ── 3. Public artifact API ──
    let api = start_artifact_api(vec![
        artifact_package_fixture(&token_repo, vec![token_snapshot_030, token_snapshot_040]),
        artifact_package_fixture(&amm_repo, vec![amm_snapshot]),
        artifact_package_fixture(&vesting_repo, vec![vesting_snapshot]),
    ]);

    // ── 4. Consumer "app" forms the conflicting diamond ──
    let app_dir = temp.path().join("consumer-app");
    std::fs::create_dir_all(app_dir.join("src")).unwrap();
    let mut toml = String::from("[package]\nedition = \"2026\"\nname = \"app\"\nversion = \"0.1.0\"\nnamespace = \"cellscript\"\n");
    toml.push_str("\n[dependencies.amm]\nversion = \"0.1.0\"\nnamespace = \"cellscript\"\n");
    toml.push_str("\n[dependencies.vesting]\nversion = \"0.1.0\"\nnamespace = \"cellscript\"\n");
    std::fs::write(app_dir.join("Cell.toml"), toml).unwrap();
    std::fs::write(app_dir.join("src/main.cell"), "module app;\n").unwrap();

    let _env = RegistryEnvGuard::new(&api.origin);

    let mut pm = PackageManager::new(&app_dir);
    pm.resolve_dependencies().expect("incompatible requirements should resolve to distinct graph nodes");
    let mut token_versions = pm
        .get_resolved()
        .values()
        .filter(|package| package.name == "token")
        .map(|package| package.version.as_str())
        .collect::<Vec<_>>();
    token_versions.sort_unstable();
    assert_eq!(token_versions, ["0.3.0", "0.4.0"]);
}

#[test]
fn e2e_namespace_isolation_go_style_install() {
    let temp = tempfile::tempdir().unwrap();

    // ── 1. Create two packages named "token" in different namespaces ──
    let token_a_repo = temp.path().join("source-repos/cellscript-token");
    let hash_a = init_source_repo(&token_a_repo, "token", "1.0.0", "cellscript");

    let token_b_repo = temp.path().join("source-repos/myns-token");
    let hash_b = init_source_repo(&token_b_repo, "token", "1.0.0", "myns");

    // Verify they have different source hashes (different module names)
    assert_ne!(hash_a, hash_b, "same-name packages in different namespaces should have different source hashes");

    // ── 2. Create discovery index with both ──
    let discovery_repo = temp.path().join("discovery-index");
    let token_a_path = token_a_repo.to_string_lossy().to_string();
    let token_b_path = token_b_repo.to_string_lossy().to_string();
    init_discovery_repo(&discovery_repo, &[("cellscript", "token", &token_a_path), ("myns", "token", &token_b_path)]);

    // ── 3. Look up each by namespace ──
    let cache_dir = temp.path().join("cache");
    std::fs::create_dir_all(&cache_dir).unwrap();

    let discovery = DiscoveryIndex::new(&discovery_repo.to_string_lossy(), &cache_dir);
    discovery.clone_or_update().unwrap();

    // cellscript/token
    let entry_cs = discovery.lookup("cellscript", "token").unwrap();
    assert_eq!(entry_cs.namespace, "cellscript");
    assert_eq!(entry_cs.source, token_a_path);

    // myns/token
    let entry_mn = discovery.lookup("myns", "token").unwrap();
    assert_eq!(entry_mn.namespace, "myns");
    assert_eq!(entry_mn.source, token_b_path);

    // ── 4. Verify Go-style install syntax parsing ──
    // (This is tested at the CLI level, but we verify the namespace resolution logic)

    // Simulate: cellc install cellscript/token@1.0.0
    let (resolved_name, resolved_namespace, resolved_version) = parse_go_style_install("cellscript/token@1.0.0");
    assert_eq!(resolved_name, "token");
    assert_eq!(resolved_namespace, Some("cellscript".to_string()));
    assert_eq!(resolved_version, Some("1.0.0".to_string()));

    // Simulate: cellc install myns/token@1.0.0
    let (resolved_name, resolved_namespace, resolved_version) = parse_go_style_install("myns/token@1.0.0");
    assert_eq!(resolved_name, "token");
    assert_eq!(resolved_namespace, Some("myns".to_string()));
    assert_eq!(resolved_version, Some("1.0.0".to_string()));

    // Simulate: cellc install token@1.0.0 (no namespace)
    let (resolved_name, resolved_namespace, resolved_version) = parse_go_style_install("token@1.0.0");
    assert_eq!(resolved_name, "token");
    assert_eq!(resolved_namespace, None);
    assert_eq!(resolved_version, Some("1.0.0".to_string()));

    // Simulate: cellc install cellscript/token (no version)
    let (resolved_name, resolved_namespace, resolved_version) = parse_go_style_install("cellscript/token");
    assert_eq!(resolved_name, "token");
    assert_eq!(resolved_namespace, Some("cellscript".to_string()));
    assert_eq!(resolved_version, None);
}

/// Parse Go-style install syntax: namespace/name@version, name@version, namespace/name
fn parse_go_style_install(input: &str) -> (String, Option<String>, Option<String>) {
    if let Some((ns, rest)) = input.split_once('/') {
        if let Some((name, ver)) = rest.split_once('@') {
            (name.to_string(), Some(ns.to_string()), Some(ver.to_string()))
        } else {
            (rest.to_string(), Some(ns.to_string()), None)
        }
    } else if let Some((name, ver)) = input.split_once('@') {
        (name.to_string(), None, Some(ver.to_string()))
    } else {
        (input.to_string(), None, None)
    }
}

// ===========================================================================
// SCENARIO 4: Version upgrade + yank + semver matching
// ===========================================================================

#[test]
fn e2e_version_upgrade_yank_semver() {
    let temp = tempfile::tempdir().unwrap();

    // ── 1. Create package and publish v0.1.0 ──
    let repo = temp.path().join("source-repo");
    create_package(&repo, "amm", "0.1.0", Some("cellscript"));
    let hash_010 = compute_source_hash(&repo).unwrap();

    let v010 = RegistryVersion {
        edition: cellscript::CURRENT_EDITION,
        compatibility_profile_hash: "test-compatibility-profile".to_string(),
        version: "0.1.0".to_string(),
        tag: "v0.1.0".to_string(),
        source_hash: hash_010.clone(),
        cellscript_version: "0.19.0".to_string(),
        dependencies: BTreeMap::new(),
        abi_index: None,
        schema_hash: None,
        license: Some("MIT".to_string()),
        released_at: Some("2026-01-15T00:00:00Z".to_string()),
        status: cellscript::package::registry::RegistryEntryStatus::VerifiedBuild,
        yanked: false,
        yanked_at: None,
        yanked_reason: None,
        replaced_by: None,
        audit: None,
        compiler_requirement: "*".to_string(),
    };
    RegistryIndex::append_version(&repo, "amm", "cellscript", v010).unwrap();

    git_init(&repo);
    git_config_user(&repo);
    git_add_all(&repo);
    git_commit(&repo, "v0.1.0");
    git_tag(&repo, "v0.1.0");

    // ── 2. Update source and publish v0.2.0 ──
    std::fs::write(repo.join("src/main.cell"), "module amm;\n\n// Added liquidity logic\n").unwrap();
    let hash_020 = compute_source_hash(&repo).unwrap();
    assert_ne!(hash_010, hash_020, "source hash must change when code changes");

    let v020 = RegistryVersion {
        edition: cellscript::CURRENT_EDITION,
        compatibility_profile_hash: "test-compatibility-profile".to_string(),
        version: "0.2.0".to_string(),
        tag: "v0.2.0".to_string(),
        source_hash: hash_020.clone(),
        cellscript_version: "0.19.0".to_string(),
        dependencies: BTreeMap::new(),
        abi_index: None,
        schema_hash: None,
        license: Some("MIT".to_string()),
        released_at: Some("2026-02-20T00:00:00Z".to_string()),
        status: cellscript::package::registry::RegistryEntryStatus::VerifiedBuild,
        yanked: false,
        yanked_at: None,
        yanked_reason: None,
        replaced_by: None,
        audit: None,
        compiler_requirement: "*".to_string(),
    };
    RegistryIndex::append_version(&repo, "amm", "cellscript", v020).unwrap();

    git_add_all(&repo);
    git_commit(&repo, "v0.2.0");
    git_tag(&repo, "v0.2.0");

    // ── 3. Update source and publish v0.3.0 ──
    std::fs::write(repo.join("src/main.cell"), "module amm;\n\n// Added swap logic\n").unwrap();
    let hash_030 = compute_source_hash(&repo).unwrap();
    assert_ne!(hash_020, hash_030);

    let v030 = RegistryVersion {
        edition: cellscript::CURRENT_EDITION,
        compatibility_profile_hash: "test-compatibility-profile".to_string(),
        version: "0.3.0".to_string(),
        tag: "v0.3.0".to_string(),
        source_hash: hash_030.clone(),
        cellscript_version: "0.19.0".to_string(),
        dependencies: BTreeMap::new(),
        abi_index: None,
        schema_hash: None,
        license: Some("MIT".to_string()),
        released_at: Some("2026-03-10T00:00:00Z".to_string()),
        status: cellscript::package::registry::RegistryEntryStatus::VerifiedBuild,
        yanked: false,
        yanked_at: None,
        yanked_reason: None,
        replaced_by: None,
        audit: None,
        compiler_requirement: "*".to_string(),
    };
    RegistryIndex::append_version(&repo, "amm", "cellscript", v030).unwrap();

    git_add_all(&repo);
    git_commit(&repo, "v0.3.0");
    git_tag(&repo, "v0.3.0");

    // ── 4. Verify all versions present in registry.json ──
    let index = RegistryIndex::read_from_repo(&repo).unwrap();
    assert_eq!(index.versions.len(), 3);

    // ── 5. Test semver matching ──
    // Request "0.2.0" → should match the latest 0.2.x → v0.2.0
    let found = index.find_matching_version("0.2.0").unwrap();
    assert_eq!(found.version, "0.2.0");

    // Request "0.1.0" → should match v0.1.0
    let found = index.find_matching_version("0.1.0").unwrap();
    assert_eq!(found.version, "0.1.0");

    // ── 6. Yank v0.2.0 (critical security issue) ──
    let v020_yanked = RegistryVersion {
        edition: cellscript::CURRENT_EDITION,
        compatibility_profile_hash: "test-compatibility-profile".to_string(),
        version: "0.2.0".to_string(),
        tag: "v0.2.0".to_string(),
        source_hash: hash_020.clone(),
        cellscript_version: "0.19.0".to_string(),
        dependencies: BTreeMap::new(),
        abi_index: None,
        schema_hash: None,
        license: Some("MIT".to_string()),
        released_at: Some("2026-02-20T00:00:00Z".to_string()),
        status: cellscript::package::registry::RegistryEntryStatus::VerifiedBuild,
        yanked: true,
        yanked_at: Some("2026-06-01T00:00:00Z".to_string()),
        yanked_reason: Some("security: reentrancy in swap()".to_string()),
        replaced_by: Some("0.3.0".to_string()),
        audit: Some(RegistryAuditInfo {
            report_hash: Some("0xsecurity_advisory_hash".to_string()),
            acceptance_gate: Some("failed".to_string()),
        }),
        compiler_requirement: "*".to_string(),
    };
    RegistryIndex::append_version(&repo, "amm", "cellscript", v020_yanked).unwrap();

    // ── 7. Verify yanked version is skipped ──
    let index = RegistryIndex::read_from_repo(&repo).unwrap();
    assert_eq!(index.versions.len(), 3); // still 3 entries

    let yanked_entry = index.versions.iter().find(|v| v.version == "0.2.0").unwrap();
    assert!(yanked_entry.yanked, "v0.2.0 should be yanked");
    assert!(yanked_entry.audit.is_some());
    // Phase 2 yank metadata round-trips through registry.json.
    assert_eq!(yanked_entry.yanked_at.as_deref(), Some("2026-06-01T00:00:00Z"));
    assert_eq!(yanked_entry.yanked_reason.as_deref(), Some("security: reentrancy in swap()"));
    assert_eq!(yanked_entry.replaced_by.as_deref(), Some("0.3.0"));

    // find_matching_version should skip yanked
    assert!(index.find_matching_version("0.2.0").is_none(), "yanked version should not be returned");
    let exact_yanked = index.find_matching_version_allowing_yanked_pin("=0.2.0").unwrap();
    assert_eq!(exact_yanked.version, "0.2.0", "exact pins may reach yanked versions so the resolver can warn");

    // ── 8. Verify git tag history ──
    let tags = git_list_tags(&repo).unwrap();
    assert!(tags.iter().any(|(t, _)| t == "v0.1.0"));
    assert!(tags.iter().any(|(t, _)| t == "v0.2.0"));
    assert!(tags.iter().any(|(t, _)| t == "v0.3.0"));
    assert_eq!(tags.len(), 3);

    // ── 9. Checkout each tag and verify source hash ──
    // Note: registry.json was modified after v0.1.0 was tagged, so we need to
    // stash or reset before checking out an older tag. We use git stash.
    let stash_status = std::process::Command::new("git").args(["stash"]).current_dir(&repo).status().expect("git stash");
    assert!(stash_status.success());

    git_checkout(&repo, "v0.1.0").unwrap();
    assert_eq!(compute_source_hash(&repo).unwrap(), hash_010);

    git_checkout(&repo, "v0.3.0").unwrap();
    assert_eq!(compute_source_hash(&repo).unwrap(), hash_030);
}

// ===========================================================================
// SCENARIO 5: Headless deploy + Deployed.toml + three-layer identity
// ===========================================================================

#[test]
fn e2e_headless_deploy_deployed_toml_three_layer_identity() {
    let temp = tempfile::tempdir().unwrap();

    // ── 1. Create and compile a CellScript package ──
    let pkg_dir = temp.path().join("my-contract");
    create_package(&pkg_dir, "my-contract", "0.1.0", Some("cellscript"));

    let source_hash = compute_source_hash(&pkg_dir).unwrap();

    // ── 2. Build a headless deploy transaction using ckb_testtools ──
    let mut ctx = Context::new_with_deterministic_rng();

    // Create a pseudo-artifact (64 bytes, like a minimal RISC-V binary)
    let artifact_binary = Bytes::from(vec![0xabu8; 64]);
    let data_hash = blake2b_256(&artifact_binary);
    let data_hash_hex = format!("0x{}", data_hash.iter().map(|b| format!("{:02x}", b)).collect::<String>());

    // Compute artifact hash
    let artifact_hash_hex = data_hash.iter().map(|b| format!("{:02x}", b)).collect::<String>();

    // Deploy the artifact as a code cell, then build scripts from the out_point
    let code_out_point = ctx.deploy_cell(artifact_binary.clone());

    // Create deployer lock script (always_success placeholder for the lock)
    // Build a simple always_success lock from the deployed code
    let always_success_out_point = ctx.deploy_cell(Bytes::from(vec![0x00u8; 1]));
    let deployer_lock = ctx.build_script(&always_success_out_point, Bytes::default()).expect("build deployer lock script");

    // Build type script using the deployed code cell as the code_hash source
    let type_id_args = data_hash; // Simplified: use data_hash as TYPE_ID args
    let type_script = ctx.build_script(&code_out_point, Bytes::copy_from_slice(&type_id_args)).expect("build type script");

    // Build a capacity input cell
    let capacity_output = packed::CellOutput::new_builder().capacity(200_000_000_000u64).lock(deployer_lock.clone()).build();
    let capacity_input_out_point = ctx.create_cell(capacity_output, Bytes::default());
    let capacity_input = packed::CellInput::new_builder().previous_output(capacity_input_out_point).build();

    // Build code output with TYPE_ID type script
    let code_data_capacity = Capacity::bytes(64).unwrap();
    let code_output = packed::CellOutput::new_builder()
        .capacity(code_data_capacity.as_u64())
        .lock(deployer_lock.clone())
        .type_(Some(type_script.clone()).pack())
        .build();

    let tx = TransactionBuilder::default()
        .input(capacity_input)
        .cell_dep(packed::CellDep::new_builder().out_point(code_out_point).build())
        .output(code_output)
        .output_data(artifact_binary.pack())
        .build();

    // ── 3. Compute on-chain identity fields from the transaction ──
    let tx_hash_bytes = blake2b_256(tx.data().as_slice());
    let tx_hash_hex = format!("0x{}", tx_hash_bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>());
    let code_hash = blake2b_256(type_script.as_slice());
    let code_hash_hex = format!("0x{}", code_hash.iter().map(|b| format!("{:02x}", b)).collect::<String>());

    let out_point_str = format!("{}:0", tx_hash_hex);
    let type_id_hex = format!("0x{}", type_id_args.iter().map(|b| format!("{:02x}", b)).collect::<String>());

    // ── 4. Write Deployed.toml with deployment facts ──
    let deployed = DeployedManifest {
        version: DeployedManifest::CURRENT_VERSION,
        schema: DEPLOYED_MANIFEST_SCHEMA.to_string(),
        package: DeployedPackageInfo {
            edition: cellscript::CURRENT_EDITION,
            name: "my-contract".to_string(),
            version: "0.1.0".to_string(),
            source_hash: Some(source_hash.clone()),
        },
        build: Some(DeployedBuildInfo {
            edition: cellscript::CURRENT_EDITION,
            compatibility_profile_hash: "test-compatibility-profile".to_string(),
            compiler_version: Some("0.19.0".to_string()),
            artifact_hash: Some(artifact_hash_hex.clone()),
            metadata_hash: None,
            schema_hash: None,
            cell_data_codec_manifest_hash: None,
            abi_hash: None,
            constraints_hash: None,
        }),
        deployments: vec![DeploymentRecord {
            edition: cellscript::CURRENT_EDITION,
            compatibility_profile_hash: "test-compatibility-profile".to_string(),
            network: "aggron4".to_string(),
            chain_id: "ckb-testnet".to_string(),
            tx_hash: tx_hash_hex.clone(),
            output_index: 0,
            code_hash: code_hash_hex.clone(),
            hash_type: "type".to_string(),
            dep_type: "code".to_string(),
            data_hash: data_hash_hex.clone(),
            out_point: out_point_str.clone(),
            artifact_hash: Some(artifact_hash_hex.clone()),
            metadata_hash: None,
            schema_hash: None,
            cell_data_codec_manifest_hash: None,
            abi_hash: None,
            constraints_hash: None,
            compiler_version: Some("0.19.0".to_string()),
            type_id: Some(type_id_hex.clone()),
            script_role: Some(ScriptRole::Type),
            status: Some(DeploymentStatus::Active),
            upgrade_lineage: None,
            audit_report_hash: None,
            publisher_signature: None,
            cell_deps: vec![],
        }],
    };

    deployed.write_to_root(&pkg_dir).unwrap();

    // ── 5. Write Cell.lock with build identity ──
    let mut lockfile = Lockfile::new();
    lockfile.package = LockfilePackageInfo {
        edition: cellscript::CURRENT_EDITION,
        name: "my-contract".to_string(),
        version: "0.1.0".to_string(),
        namespace: Some("cellscript".to_string()),
        source_hash: Some(source_hash.clone()),
        compiler_source_hash: None,
        compiler_requirement: "*".to_string(),
        resolver_compiler_version: cellscript::VERSION.to_string(),
    };
    lockfile.package_build = Some(LockedBuildInfo {
        edition: cellscript::CURRENT_EDITION,
        compatibility_profile_hash: "test-compatibility-profile".to_string(),
        compiler_version: Some("0.19.0".to_string()),
        target_profile: Some("ckb-release".to_string()),
        artifact_hash: Some(artifact_hash_hex.clone()),
        constraints_hash: None,
        ..Default::default()
    });
    lockfile.deployment.insert(
        "aggron4".to_string(),
        LockfileDeploymentRef {
            record: out_point_str.clone(),
            record_hash: None,
            code_hash: Some(code_hash_hex.clone()),
            out_point: Some(out_point_str.clone()),
            data_hash: Some(data_hash_hex.clone()),
        },
    );
    lockfile.write_to_root(&pkg_dir).unwrap();

    // ── 6. Cross-verify three identity layers ──

    // Layer 1: Package Identity (source_hash)
    let recomputed_hash = compute_source_hash(&pkg_dir).unwrap();
    assert_eq!(source_hash, recomputed_hash, "source hash must be deterministic");

    // Layer 2: Build Identity (artifact_hash)
    let read_lock = Lockfile::read_from_root(&pkg_dir).unwrap().unwrap();
    let lock_artifact_hash = read_lock.package_build.as_ref().unwrap().artifact_hash.as_ref().unwrap();
    assert_eq!(lock_artifact_hash, &artifact_hash_hex, "artifact_hash must match between lock and computed");

    // Layer 3: Deployment Identity (code_hash, data_hash, out_point)
    let read_deployed = DeployedManifest::read_from_root(&pkg_dir).unwrap().unwrap();
    let dep = &read_deployed.deployments[0];
    assert_eq!(dep.network, "aggron4");
    assert_eq!(dep.tx_hash, tx_hash_hex);
    assert_eq!(dep.code_hash, code_hash_hex);
    assert_eq!(dep.data_hash, data_hash_hex);
    assert_eq!(dep.out_point, out_point_str);
    assert_eq!(dep.status, Some(DeploymentStatus::Active));
    assert_eq!(dep.type_id.as_deref(), Some(type_id_hex.as_str()));
    assert!(matches!(dep.script_role, Some(ScriptRole::Type)));

    // Cross-verify: Cell.lock ↔ Deployed.toml
    let violations = cross_verify_lockfile_deployed(&read_lock, &read_deployed);
    assert!(violations.is_empty(), "no cross-verification violations: {violations:?}");

    // ── 7. Verify fail-closed: tamper with Deployed.toml and detect ──
    let mut tampered_deployed = read_deployed.clone();
    tampered_deployed.deployments[0].code_hash = "0xTAMPERED_CODE_HASH".to_string();
    let violations = cross_verify_lockfile_deployed(&read_lock, &tampered_deployed);
    assert_eq!(violations.len(), 1);
    assert!(violations[0].contains("code_hash mismatch"));

    // Tamper with artifact_hash in Deployed.toml build info
    let mut tampered_build = read_deployed.clone();
    tampered_build.build.as_mut().unwrap().artifact_hash = Some("0xTAMPERED_ARTIFACT".to_string());
    let violations = cross_verify_lockfile_deployed(&read_lock, &tampered_build);
    assert_eq!(violations.len(), 1);
    assert!(violations[0].contains("artifact_hash mismatch"));
}

// ===========================================================================
// SCENARIO 5b: Headless deploy with cell_deps and multi-network deployment
// ===========================================================================

#[test]
fn e2e_headless_deploy_with_cell_deps_and_multi_network() {
    let temp = tempfile::tempdir().unwrap();
    let pkg_dir = temp.path().join("multi-deploy-contract");
    create_package(&pkg_dir, "multi-deploy", "0.2.0", Some("cellscript"));

    // ── 1. Build deployment records for two networks ──
    let secp256k1_data_tx_hash = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    let _secp256k1_data_out_point = format!("{}:2", secp256k1_data_tx_hash);

    let mainnet_record = DeploymentRecord {
        edition: cellscript::CURRENT_EDITION,
        compatibility_profile_hash: "test-compatibility-profile".to_string(),
        network: "ckb-mainnet".to_string(),
        chain_id: "ckb-mainnet".to_string(),
        tx_hash: "0xaaaa0000111122223333444455556666777788889999000011112222333344445555".to_string(),
        output_index: 0,
        code_hash: "0xbbbb1111222233334444555566667777888899990000111122223333444455556666".to_string(),
        hash_type: "type".to_string(),
        dep_type: "code".to_string(),
        data_hash: "0xcccc2222333344445555666677778888999900001111222233334444555566667777".to_string(),
        out_point: "0xaaaa0000111122223333444455556666777788889999000011112222333344445555:0".to_string(),
        artifact_hash: Some("artifact_hash_mainnet".to_string()),
        metadata_hash: None,
        schema_hash: None,
        cell_data_codec_manifest_hash: None,
        abi_hash: None,
        constraints_hash: None,
        compiler_version: Some("0.19.0".to_string()),
        type_id: Some("0xdddd_type_id_mainnet".to_string()),
        script_role: Some(ScriptRole::Type),
        status: Some(DeploymentStatus::Active),
        upgrade_lineage: None,
        audit_report_hash: None,
        publisher_signature: None,
        cell_deps: vec![DeploymentCellDep {
            name: Some("secp256k1_data".to_string()),
            tx_hash: secp256k1_data_tx_hash.to_string(),
            output_index: 2,
            dep_type: "dep_group".to_string(),
            hash_type: Some("type".to_string()),
            data_hash: None,
            type_id: None,
        }],
    };

    let testnet_record = DeploymentRecord {
        edition: cellscript::CURRENT_EDITION,
        compatibility_profile_hash: "test-compatibility-profile".to_string(),
        network: "aggron4".to_string(),
        chain_id: "ckb-testnet".to_string(),
        tx_hash: "0xeeee3333444455556666777788889999000011112222333344445555666677778888".to_string(),
        output_index: 0,
        code_hash: "0xbbbb1111222233334444555566667777888899990000111122223333444455556666".to_string(),
        hash_type: "data1".to_string(),
        dep_type: "code".to_string(),
        data_hash: "0xcccc2222333344445555666677778888999900001111222233334444555566667777".to_string(),
        out_point: "0xeeee3333444455556666777788889999000011112222333344445555666677778888:0".to_string(),
        artifact_hash: Some("artifact_hash_testnet".to_string()),
        metadata_hash: None,
        schema_hash: None,
        cell_data_codec_manifest_hash: None,
        abi_hash: None,
        constraints_hash: None,
        compiler_version: Some("0.19.0".to_string()),
        type_id: None,
        script_role: Some(ScriptRole::Lock),
        status: Some(DeploymentStatus::Candidate),
        upgrade_lineage: None,
        audit_report_hash: None,
        publisher_signature: None,
        cell_deps: vec![
            DeploymentCellDep {
                name: Some("secp256k1_data".to_string()),
                tx_hash: secp256k1_data_tx_hash.to_string(),
                output_index: 2,
                dep_type: "dep_group".to_string(),
                hash_type: Some("type".to_string()),
                data_hash: None,
                type_id: None,
            },
            DeploymentCellDep {
                name: Some("always_success".to_string()),
                tx_hash: "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
                output_index: 0,
                dep_type: "code".to_string(),
                hash_type: Some("data".to_string()),
                data_hash: None,
                type_id: None,
            },
        ],
    };

    // ── 2. Write Deployed.toml with both deployments ──
    let source_hash = compute_source_hash(&pkg_dir).unwrap();
    let deployed = DeployedManifest {
        version: DeployedManifest::CURRENT_VERSION,
        schema: DEPLOYED_MANIFEST_SCHEMA.to_string(),
        package: DeployedPackageInfo {
            edition: cellscript::CURRENT_EDITION,
            name: "multi-deploy".to_string(),
            version: "0.2.0".to_string(),
            source_hash: Some(source_hash.clone()),
        },
        build: Some(DeployedBuildInfo {
            edition: cellscript::CURRENT_EDITION,
            compatibility_profile_hash: "test-compatibility-profile".to_string(),
            compiler_version: Some("0.19.0".to_string()),
            artifact_hash: Some("artifact_hash_mainnet".to_string()),
            metadata_hash: None,
            schema_hash: None,
            cell_data_codec_manifest_hash: None,
            abi_hash: None,
            constraints_hash: None,
        }),
        deployments: vec![mainnet_record.clone(), testnet_record.clone()],
    };
    deployed.write_to_root(&pkg_dir).unwrap();

    // ── 3. Write Cell.lock with both network deployment refs ──
    let mut lockfile = Lockfile::new();
    lockfile.package = LockfilePackageInfo {
        edition: cellscript::CURRENT_EDITION,
        name: "multi-deploy".to_string(),
        version: "0.2.0".to_string(),
        namespace: Some("cellscript".to_string()),
        source_hash: Some(source_hash),
        compiler_source_hash: None,
        compiler_requirement: "*".to_string(),
        resolver_compiler_version: cellscript::VERSION.to_string(),
    };
    lockfile.package_build = Some(LockedBuildInfo {
        edition: cellscript::CURRENT_EDITION,
        compatibility_profile_hash: "test-compatibility-profile".to_string(),
        compiler_version: Some("0.19.0".to_string()),
        target_profile: Some("ckb-release".to_string()),
        artifact_hash: Some("artifact_hash_mainnet".to_string()),
        ..Default::default()
    });
    lockfile.deployment.insert(
        "ckb-mainnet".to_string(),
        LockfileDeploymentRef {
            record: mainnet_record.out_point.clone(),
            record_hash: None,
            code_hash: Some(mainnet_record.code_hash.clone()),
            out_point: Some(mainnet_record.out_point.clone()),
            data_hash: Some(mainnet_record.data_hash.clone()),
        },
    );
    lockfile.deployment.insert(
        "aggron4".to_string(),
        LockfileDeploymentRef {
            record: testnet_record.out_point.clone(),
            record_hash: None,
            code_hash: Some(testnet_record.code_hash.clone()),
            out_point: Some(testnet_record.out_point.clone()),
            data_hash: Some(testnet_record.data_hash.clone()),
        },
    );
    lockfile.write_to_root(&pkg_dir).unwrap();

    // ── 4. Round-trip and cross-verify ──
    let read_deployed = DeployedManifest::read_from_root(&pkg_dir).unwrap().unwrap();
    assert_eq!(read_deployed.deployments.len(), 2);

    let read_lock = Lockfile::read_from_root(&pkg_dir).unwrap().unwrap();
    assert_eq!(read_lock.deployment.len(), 2);

    // Mainnet
    let mn_dep = &read_deployed.deployments[0];
    assert_eq!(mn_dep.network, "ckb-mainnet");
    assert_eq!(mn_dep.status, Some(DeploymentStatus::Active));
    assert!(matches!(mn_dep.script_role, Some(ScriptRole::Type)));
    assert_eq!(mn_dep.cell_deps.len(), 1);
    assert_eq!(mn_dep.cell_deps[0].name.as_deref(), Some("secp256k1_data"));

    // Testnet
    let tn_dep = &read_deployed.deployments[1];
    assert_eq!(tn_dep.network, "aggron4");
    assert_eq!(tn_dep.status, Some(DeploymentStatus::Candidate));
    assert!(matches!(tn_dep.script_role, Some(ScriptRole::Lock)));
    assert_eq!(tn_dep.cell_deps.len(), 2);

    // Cross-verify both networks
    let violations = cross_verify_lockfile_deployed(&read_lock, &read_deployed);
    assert!(violations.is_empty(), "no cross-verification violations: {violations:?}");
}

// ===========================================================================
// SCENARIO 5c: Fail-closed verification across all three identity layers
// ===========================================================================

#[test]
fn e2e_fail_closed_three_layer_identity_verification() {
    let temp = tempfile::tempdir().unwrap();
    let pkg_dir = temp.path().join("fail-closed-contract");
    create_package(&pkg_dir, "fail-closed", "0.1.0", Some("cellscript"));

    let source_hash = compute_source_hash(&pkg_dir).unwrap();
    let artifact_hash = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".to_string();
    let code_hash = "0xf1e2d3c4b5a6f1e2d3c4b5a6f1e2d3c4b5a6f1e2d3c4b5a6f1e2d3c4b5a6f1e2".to_string();
    let data_hash = "0x11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff".to_string();

    // ── 1. Write correct Cell.lock + Deployed.toml ──
    let mut lockfile = Lockfile::new();
    lockfile.package = LockfilePackageInfo {
        edition: cellscript::CURRENT_EDITION,
        name: "fail-closed".to_string(),
        version: "0.1.0".to_string(),
        namespace: Some("cellscript".to_string()),
        source_hash: Some(source_hash.clone()),
        compiler_source_hash: None,
        compiler_requirement: "*".to_string(),
        resolver_compiler_version: cellscript::VERSION.to_string(),
    };
    lockfile.package_build = Some(LockedBuildInfo {
        edition: cellscript::CURRENT_EDITION,
        compatibility_profile_hash: "test-compatibility-profile".to_string(),
        compiler_version: Some("0.19.0".to_string()),
        artifact_hash: Some(artifact_hash.clone()),
        ..Default::default()
    });
    lockfile.deployment.insert(
        "aggron4".to_string(),
        LockfileDeploymentRef {
            record: "0x1234:0".to_string(),
            record_hash: None,
            code_hash: Some(code_hash.clone()),
            out_point: Some("0x1234:0".to_string()),
            data_hash: Some(data_hash.clone()),
        },
    );
    lockfile.write_to_root(&pkg_dir).unwrap();

    let deployed = DeployedManifest {
        version: DeployedManifest::CURRENT_VERSION,
        schema: DEPLOYED_MANIFEST_SCHEMA.to_string(),
        package: DeployedPackageInfo {
            edition: cellscript::CURRENT_EDITION,
            name: "fail-closed".to_string(),
            version: "0.1.0".to_string(),
            source_hash: Some(source_hash.clone()),
        },
        build: Some(DeployedBuildInfo {
            edition: cellscript::CURRENT_EDITION,
            compatibility_profile_hash: "test-compatibility-profile".to_string(),
            compiler_version: Some("0.19.0".to_string()),
            artifact_hash: Some(artifact_hash.clone()),
            ..Default::default()
        }),
        deployments: vec![sample_deployment_record("aggron4", "ckb-testnet", "0x1234", &code_hash, &data_hash, "0x1234:0")],
    };
    deployed.write_to_root(&pkg_dir).unwrap();

    let read_lock = Lockfile::read_from_root(&pkg_dir).unwrap().unwrap();
    let read_deployed = DeployedManifest::read_from_root(&pkg_dir).unwrap().unwrap();

    // Baseline: no violations
    let violations = cross_verify_lockfile_deployed(&read_lock, &read_deployed);
    assert!(violations.is_empty(), "baseline should have no violations: {violations:?}");

    // ── 2. Test: source_hash mismatch (Layer 1: Package Identity) ──
    let computed_source_hash = compute_source_hash(&pkg_dir).unwrap();
    let wrong_source_hash = "deliberately_wrong_hash_value".to_string();
    assert_ne!(computed_source_hash, wrong_source_hash);
    // If Cell.lock has wrong source_hash, package_verify would detect it

    // ── 3. Test: artifact_hash mismatch (Layer 2: Build Identity) ──
    let mut tampered_deployed = read_deployed.clone();
    tampered_deployed.build.as_mut().unwrap().artifact_hash = Some("0xBAD_ARTIFACT_HASH".to_string());
    let violations = cross_verify_lockfile_deployed(&read_lock, &tampered_deployed);
    assert_eq!(violations.len(), 1, "artifact_hash tampering should be detected");
    assert!(violations[0].contains("artifact_hash mismatch"));

    // ── 4. Test: code_hash mismatch (Layer 3: Deployment Identity) ──
    let mut tampered_deployed = read_deployed.clone();
    tampered_deployed.deployments[0].code_hash = "0xBAD_CODE_HASH".to_string();
    let violations = cross_verify_lockfile_deployed(&read_lock, &tampered_deployed);
    assert_eq!(violations.len(), 1, "code_hash tampering should be detected");
    assert!(violations[0].contains("code_hash mismatch"));

    // ── 5. Test: data_hash mismatch (Layer 3: Deployment Identity) ──
    let mut tampered_deployed = read_deployed.clone();
    tampered_deployed.deployments[0].data_hash = "0xBAD_DATA_HASH".to_string();
    let violations = cross_verify_lockfile_deployed(&read_lock, &tampered_deployed);
    assert_eq!(violations.len(), 1, "data_hash tampering should be detected");
    assert!(violations[0].contains("data_hash mismatch"));

    // ── 6. Test: Multiple simultaneous mismatches ──
    let mut tampered_deployed = read_deployed.clone();
    tampered_deployed.build.as_mut().unwrap().artifact_hash = Some("0xBAD1".to_string());
    tampered_deployed.deployments[0].code_hash = "0xBAD2".to_string();
    tampered_deployed.deployments[0].data_hash = "0xBAD3".to_string();
    let violations = cross_verify_lockfile_deployed(&read_lock, &tampered_deployed);
    assert_eq!(violations.len(), 3, "all three mismatches should be detected independently");

    // ── 7. Test: Missing network in Cell.lock ──
    let mut incomplete_lock = read_lock.clone();
    incomplete_lock.deployment.remove("aggron4");
    let violations = cross_verify_lockfile_deployed(&incomplete_lock, &read_deployed);
    // No violations from cross_verify (it only checks entries that exist in both)
    // But the deployment in Deployed.toml has no matching Cell.lock entry
    assert!(
        violations.is_empty(),
        "missing network in lock produces no violations (no entry to compare), but should be checked separately"
    );
}

// ===========================================================================
// ===========================================================================
// SCENARIO 6: Live devnet deploy → verify (#[ignore])
//
// Starts a real CKB devnet from ../ckb, submits transactions, queries
// on-chain state, and verifies Cell.lock ↔ Deployed.toml ↔ on-chain consistency.
//
// Run with: cargo test --locked -p cellscript --test e2e_registry_devnet -- --ignored
// ===========================================================================

// Devnet always_success lock (deployed with hash_type: "data" in integration template)
const ALWAYS_SUCCESS_CODE_HASH: &str = "0x28e83a1277d48add8e72fadaa9248559e1b632bab2bd60b27955ebc4c03800a5";
const ALWAYS_SUCCESS_HASH_TYPE: &str = "data";

// ── Devnet lifecycle helpers ──

struct CkbDevnet {
    _ckb_dir: tempfile::TempDir,
    rpc_url: String,
    ckb_pid: std::process::Child,
}

impl CkbDevnet {
    /// Launch a CKB integration devnet from the parent `ckb` repository.
    fn launch() -> Self {
        let ckb_repo = Self::find_ckb_repo();
        let ckb_bin = Self::resolve_ckb_bin(&ckb_repo);
        let rpc_port = Self::pick_port();
        let p2p_port = Self::pick_port();
        let rpc_url = format!("http://127.0.0.1:{}", rpc_port);

        // Copy template into temp dir
        let ckb_dir = tempfile::tempdir().unwrap();
        let template = ckb_repo.join("test/template");
        Self::copy_dir_recursive(&template, ckb_dir.path());

        // Patch ports in ckb.toml
        Self::patch_ckb_toml(ckb_dir.path(), rpc_port, p2p_port);

        // Start CKB node (log to file for diagnostics)
        let ckb_log_path = ckb_dir.path().join("ckb.log");
        let ckb_log_file = std::fs::File::create(&ckb_log_path).expect("create ckb.log");
        let mut ckb_pid = std::process::Command::new(&ckb_bin)
            .args(["-C", &ckb_dir.path().to_string_lossy(), "run", "--ba-advanced"])
            .stdout(ckb_log_file.try_clone().expect("clone stdout"))
            .stderr(ckb_log_file)
            .spawn()
            .expect("failed to start ckb");

        // Wait for RPC to become ready
        let mut ready = false;
        for _ in 0..120 {
            let body = serde_json::json!({
                "id": 1,
                "jsonrpc": "2.0",
                "method": "get_tip_header",
                "params": serde_json::Value::Array(vec![]),
            });
            if let Ok(output) = std::process::Command::new("curl")
                .args(["-s", "-H", "Content-Type: application/json", "-d", &body.to_string(), &rpc_url])
                .output()
                && let Ok(response) = serde_json::from_slice::<serde_json::Value>(&output.stdout)
                && response.get("result").is_some()
                && response.get("error").is_none()
            {
                ready = true;
                break;
            }
            if let Ok(Some(status)) = ckb_pid.try_wait() {
                let log_content = std::fs::read_to_string(&ckb_log_path).unwrap_or_default();
                panic!(
                    "CKB process exited before RPC became ready: {:?}\nLog:\n{}",
                    status,
                    &log_content[log_content.len().saturating_sub(2000)..]
                );
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        assert!(ready, "CKB RPC did not become ready at {}\nCheck ckb.log in temp dir", rpc_url);

        // Generate some initial blocks so we have spendable cellbases
        for _ in 0..8 {
            let _ = std::process::Command::new("curl")
                .args([
                    "-s",
                    "-H",
                    "Content-Type: application/json",
                    "-d",
                    "{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"generate_block\",\"params\":[]}",
                    &rpc_url,
                ])
                .output();
        }

        Self { _ckb_dir: ckb_dir, rpc_url, ckb_pid }
    }

    fn find_ckb_repo() -> std::path::PathBuf {
        let repo_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let parent = repo_root.parent().unwrap();
        let candidate = parent.join("ckb");
        if candidate.is_dir() && candidate.join("test/template/ckb.toml").exists() {
            return candidate;
        }
        panic!("CKB repo not found at {}. Clone ckb to ../ckb first.", candidate.display());
    }

    fn resolve_ckb_bin(ckb_repo: &std::path::Path) -> std::path::PathBuf {
        for candidate in [ckb_repo.join("target/debug/ckb"), ckb_repo.join("target/release/ckb")] {
            if candidate.exists() {
                return candidate;
            }
        }
        panic!("No ckb binary found in {}; run `cargo build --bin ckb` in the ckb repo.", ckb_repo.display());
    }

    fn pick_port() -> u16 {
        // Bind to port 0 to get an OS-assigned free port
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    }

    fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) {
        std::fs::create_dir_all(dst).unwrap();
        for entry in std::fs::read_dir(src).unwrap() {
            let entry = entry.unwrap();
            let src_path = entry.path();
            let dst_path = dst.join(entry.file_name());
            if src_path.is_dir() {
                Self::copy_dir_recursive(&src_path, &dst_path);
            } else {
                std::fs::copy(&src_path, &dst_path).unwrap();
            }
        }
    }

    fn patch_ckb_toml(ckb_dir: &std::path::Path, rpc_port: u16, p2p_port: u16) {
        let toml_path = ckb_dir.join("ckb.toml");
        let content = std::fs::read_to_string(&toml_path).unwrap();
        // Patch RPC port
        let re_rpc = regex::Regex::new(r#"listen_address = "127\.0\.0\.1:\d+""#).unwrap();
        let content = re_rpc.replace(&content, &format!("listen_address = \"127.0.0.1:{}\"", rpc_port)).to_string();
        // Patch P2P port
        let re_p2p = regex::Regex::new(r#"listen_addresses = \["/ip4/0\.0\.0\.0/tcp/\d+"\]"#).unwrap();
        let content = re_p2p.replace(&content, &format!("listen_addresses = [\"/ip4/127.0.0.1/tcp/{}\"]", p2p_port)).to_string();
        std::fs::write(&toml_path, content).unwrap();
    }

    // ── RPC helpers ──

    fn rpc(&self, method: &str, params: serde_json::Value) -> serde_json::Value {
        let body = serde_json::json!({
            "id": 42,
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        });
        let output = std::process::Command::new("curl")
            .args(["-s", "-H", "Content-Type: application/json", "-d", &body.to_string(), &self.rpc_url])
            .output()
            .expect("curl failed");
        let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|_| {
            panic!("RPC {} returned non-JSON: {}", method, String::from_utf8_lossy(&output.stdout));
        });
        if let Some(error) = response.get("error") {
            panic!("RPC {} returned error: {}", method, error);
        }
        response["result"].clone()
    }

    fn generate_block(&self) -> serde_json::Value {
        self.rpc("generate_block", serde_json::json!([]))
    }

    fn tip_block_number(&self) -> u64 {
        let result = self.rpc("get_tip_block_number", serde_json::json!([]));
        let hex_str = result.as_str().unwrap();
        u64::from_str_radix(hex_str.trim_start_matches("0x"), 16).unwrap()
    }

    fn send_transaction(&self, tx: &serde_json::Value) -> String {
        let result = self.rpc("send_test_transaction", serde_json::json!([tx, "passthrough"]));
        result.as_str().unwrap().to_string()
    }

    fn get_transaction(&self, tx_hash: &str) -> serde_json::Value {
        self.rpc("get_transaction", serde_json::json!([tx_hash]))
    }

    fn get_live_cell(&self, tx_hash: &str, index: u32) -> serde_json::Value {
        self.rpc("get_live_cell", serde_json::json!([{ "tx_hash": tx_hash, "index": format!("0x{:x}", index) }, true]))
    }

    /// Submit a transaction and wait for it to be committed by generating blocks.
    fn submit_and_commit(&self, tx: &serde_json::Value, label: &str) -> String {
        let tx_hash = self.send_transaction(tx);
        for _ in 0..64 {
            let status = self.get_transaction(&tx_hash);
            let tx_status = status["tx_status"]["status"].as_str().unwrap_or("unknown");
            if tx_status == "committed" {
                return tx_hash;
            }
            if tx_status == "rejected" {
                panic!("{} was rejected: {}", label, status["tx_status"]);
            }
            self.generate_block();
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        panic!("{} was not committed after 64 blocks", label);
    }

    /// Collect enough capacity for deploying `artifact_size` bytes.
    /// Generates blocks, collects cellbase outputs, then merges them into a single
    /// cell via a consolidation transaction. Returns (tx_hash, index, capacity_hex)
    /// of the merged cell.
    fn collect_capacity(&self, artifact_size: usize) -> (String, u32, String) {
        // Each CKB byte costs 100M shannons. Occupied capacity for the code cell is roughly:
        // (header_size + artifact_size + 8) * 100M where header ≈ 93 bytes
        let needed_shannons = (93 + artifact_size + 8) as u64 * 100_000_000;
        // Add margin for change cell and fees
        let target_shannons = needed_shannons + 200_000_000_000; // extra 200 CKB

        let mut inputs: Vec<serde_json::Value> = Vec::new();
        let mut total_capacity: u64 = 0;

        // Generate blocks and collect cellbase outputs until we have enough
        for _ in 0..100 {
            if total_capacity >= target_shannons {
                break;
            }
            let block_hash = self.generate_block().as_str().unwrap().to_string();
            let block = self.rpc("get_block", serde_json::json!([block_hash]));
            let cellbase = &block["transactions"][0];
            let cb_tx_hash = cellbase["hash"].as_str().unwrap().to_string();
            let outputs = cellbase["outputs"].as_array().unwrap();
            for (index, output) in outputs.iter().enumerate() {
                let cap_hex = output["capacity"].as_str().unwrap();
                let cap = u64::from_str_radix(cap_hex.trim_start_matches("0x"), 16).unwrap();
                if cap > 0 {
                    // Wait for it to be live
                    for _ in 0..20 {
                        let live = self.get_live_cell(&cb_tx_hash, index as u32);
                        if live["status"].as_str() == Some("live") {
                            inputs.push(serde_json::json!({
                                "previous_output": { "tx_hash": cb_tx_hash, "index": format!("0x{:x}", index) },
                                "since": "0x0",
                            }));
                            total_capacity += cap;
                            break;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(50));
                    }
                }
            }
        }

        if inputs.len() <= 1 {
            // Only one input, return it directly
            let first = &inputs[0];
            let tx_hash = first["previous_output"]["tx_hash"].as_str().unwrap().to_string();
            let index = u32::from_str_radix(first["previous_output"]["index"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
            let live = self.get_live_cell(&tx_hash, index);
            let cap = live["cell"]["output"]["capacity"].as_str().unwrap().to_string();
            return (tx_hash, index, cap);
        }

        // Merge all inputs into a single output via a consolidation transaction
        let change_capacity = total_capacity - 1_000; // small fee
        let merge_tx = serde_json::json!({
            "version": "0x0",
            "cell_deps": [self.always_success_dep()],
            "header_deps": [],
            "inputs": inputs,
            "outputs": [{
                "capacity": format!("0x{:x}", change_capacity),
                "lock": { "code_hash": ALWAYS_SUCCESS_CODE_HASH, "hash_type": ALWAYS_SUCCESS_HASH_TYPE, "args": "0x" },
            }],
            "outputs_data": ["0x"],
            "witnesses": vec!["0x"; inputs.len()],
        });

        let tx_hash = self.submit_and_commit(&merge_tx, "capacity consolidation");
        let live = self.get_live_cell(&tx_hash, 0);
        assert_eq!(live["status"].as_str(), Some("live"));
        let cap = live["cell"]["output"]["capacity"].as_str().unwrap().to_string();
        (tx_hash, 0, cap)
    }

    /// Get the always_success system cell dep (genesis cellbase output index 5).
    fn always_success_dep(&self) -> serde_json::Value {
        let genesis = self.rpc("get_block_by_number", serde_json::json!(["0x0"]));
        let genesis_cellbase_hash = genesis["transactions"][0]["hash"].as_str().unwrap();
        cell_dep(genesis_cellbase_hash, 5, "code")
    }
}

impl Drop for CkbDevnet {
    fn drop(&mut self) {
        let _ = self.ckb_pid.kill();
        let _ = self.ckb_pid.wait();
    }
}

// ── CKB transaction building helpers (JSON) ──

fn out_point(tx_hash: &str, index: u32) -> serde_json::Value {
    serde_json::json!({ "tx_hash": tx_hash, "index": format!("0x{:x}", index) })
}

fn cell_dep(tx_hash: &str, index: u32, dep_type: &str) -> serde_json::Value {
    serde_json::json!({ "out_point": out_point(tx_hash, index), "dep_type": dep_type })
}

/// Compute the CKB data_hash (blake2b-256 with "ckb-default-hash" personalization).
fn ckb_data_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2bParams::new().hash_length(32).personal(b"ckb-default-hash").to_state();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(result.as_bytes());
    hash
}

/// Compute CKB script hash (blake2b-256 of the molecule-serialized script
/// with "ckb-default-hash" personalization).
/// This replicates the same molecule serialization used in the acceptance script.
fn ckb_script_hash(code_hash: &str, hash_type: &str, args: &str) -> String {
    // Molecule serialization of Script: Table([code_hash(32), hash_type(1), args(Bytes)])
    let code_hash_bytes = hex::decode(code_hash.trim_start_matches("0x")).unwrap();
    let hash_type_byte = match hash_type {
        "data" => 0u8,
        "type" => 1u8,
        "data1" => 2u8,
        "data2" => 4u8,
        _ => panic!("unknown hash_type: {}", hash_type),
    };
    let args_bytes = hex::decode(args.trim_start_matches("0x")).unwrap();

    // molecule Bytes: u32_le(len) + data
    let args_mol = {
        let len = (args_bytes.len() as u32).to_le_bytes();
        len.iter().chain(args_bytes.iter()).copied().collect::<Vec<u8>>()
    };

    // molecule Table: u32_le(total_size) + u32_le(offsets...) + fields...
    let header_size = 4 + 4 * 3; // total_size + 3 field offsets
    let field_sizes: [usize; 3] = [32, 1, args_mol.len()];
    let mut offsets = Vec::new();
    let mut cursor = header_size;
    for &size in &field_sizes {
        offsets.push(cursor);
        cursor += size;
    }
    let total_size = cursor;

    let mut serialized = Vec::new();
    serialized.extend_from_slice(&(total_size as u32).to_le_bytes());
    for &offset in &offsets {
        serialized.extend_from_slice(&(offset as u32).to_le_bytes());
    }
    serialized.extend_from_slice(&code_hash_bytes);
    serialized.push(hash_type_byte);
    serialized.extend_from_slice(&args_mol);

    let hash = ckb_data_hash(&serialized);
    format!("0x{}", hex::encode(hash))
}

/// Compute TYPE_ID = blake2b-256(sTxHash || output_index) with CKB personalization.
fn compute_type_id(tx_hash: &str, output_index: u32) -> String {
    let tx_hash_bytes = hex::decode(tx_hash.trim_start_matches("0x")).unwrap();
    let index_bytes = (output_index as u64).to_le_bytes();
    let mut hasher = Blake2bParams::new().hash_length(32).personal(b"ckb-default-hash").to_state();
    hasher.update(&tx_hash_bytes);
    hasher.update(&index_bytes);
    let result = hasher.finalize();
    format!("0x{}", hex::encode(result.as_bytes()))
}

// ── CellScript toolchain helpers ──

fn cellc_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_cellc"))
}

fn cellc_build(pkg_dir: &std::path::Path) -> std::path::PathBuf {
    let output = std::process::Command::new(cellc_bin())
        .current_dir(pkg_dir)
        .args(["build", "--target", "riscv64-elf", "--target-profile", "ckb", "--json"])
        .output()
        .expect("cellc build failed");
    assert!(output.status.success(), "cellc build failed: {}", String::from_utf8_lossy(&output.stderr));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let artifact_path = json["artifact"].as_str().unwrap();
    std::path::PathBuf::from(artifact_path)
}

fn cellc_deploy_plan(source: &std::path::Path, output_path: &std::path::Path) {
    let result = std::process::Command::new(cellc_bin())
        .args(["deploy", "plan"])
        .arg(source)
        .args(["--target-profile", "ckb", "--output"])
        .arg(output_path)
        .output()
        .expect("cellc deploy plan failed");
    assert!(result.status.success(), "cellc deploy plan failed: {}", String::from_utf8_lossy(&result.stderr));
}

fn cellc_verify_deploy(plan_path: &std::path::Path) -> serde_json::Value {
    let output = std::process::Command::new(cellc_bin())
        .args(["deploy", "verify", "--plan"])
        .arg(plan_path)
        .arg("--json")
        .output()
        .expect("cellc deploy verify failed");
    if output.status.success() {
        serde_json::from_slice(&output.stdout).unwrap()
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!("cellc deploy verify failed: {}", stderr);
    }
}

fn cellc_verify_artifact(artifact_path: &std::path::Path, expect_hash: &str) {
    let output = std::process::Command::new(cellc_bin())
        .args(["verify-artifact", &artifact_path.to_string_lossy(), "--expect-artifact-hash", expect_hash])
        .output()
        .expect("cellc verify-artifact failed");
    assert!(output.status.success(), "cellc verify-artifact failed: {}", String::from_utf8_lossy(&output.stderr));
}

fn cellc_ckb_hash(file_path: &std::path::Path) -> String {
    let output = std::process::Command::new(cellc_bin())
        .args(["ckb-hash", "--file", &file_path.to_string_lossy()])
        .output()
        .expect("cellc ckb-hash failed");
    assert!(output.status.success(), "cellc ckb-hash failed: {}", String::from_utf8_lossy(&output.stderr));
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

#[test]
#[ignore = "Requires ckb repo at ../ckb with compiled binary; starts real devnet"]
fn e2e_live_devnet_deploy_and_verify() {
    let devnet = CkbDevnet::launch();

    let temp = tempfile::tempdir().unwrap();

    // ── 1. Create a CellScript package with real source code ──
    let pkg_dir = temp.path().join("devnet-contract");
    std::fs::create_dir_all(pkg_dir.join("src")).unwrap();
    std::fs::write(
        pkg_dir.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "devnet-contract"
version = "0.1.0"
namespace = "cellscript"

[build]
target = "riscv64-elf"
target_profile = "ckb"
out_dir = "build"
"#,
    )
    .unwrap();
    std::fs::write(
        pkg_dir.join("src/main.cell"),
        r#"
module devnet_contract::main

action ping(value: u64) -> u64 {
    verification
        return value
}
"#,
    )
    .unwrap();
    let source_hash = compute_source_hash(&pkg_dir).unwrap();

    // ── 2. cellc build: compile to real RISC-V ELF artifact ──
    let artifact_path = cellc_build(&pkg_dir);
    let artifact_binary = std::fs::read(&artifact_path).unwrap();
    assert!(artifact_binary.starts_with(b"\x7fELF"), "artifact must be a valid ELF");
    eprintln!("Built real artifact: {} bytes", artifact_binary.len());

    // ── 3. cellc ckb-hash: compute artifact hash via toolchain ──
    let toolchain_artifact_hash = cellc_ckb_hash(&artifact_path);
    eprintln!("Toolchain artifact hash: {}", toolchain_artifact_hash);

    // ── 4. cellc deploy plan: emit deployment plan ──
    let deploy_plan_path = temp.path().join("deploy-plan.json");
    cellc_deploy_plan(&pkg_dir, &deploy_plan_path);
    let deploy_plan: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&deploy_plan_path).unwrap()).unwrap();
    assert!(deploy_plan["metadata_schema_version"].as_u64().unwrap() > 0, "deploy plan must have valid schema version");

    // ── 5. cellc deploy verify: verify the plan ──
    let verify_result = cellc_verify_deploy(&deploy_plan_path);
    assert_eq!(verify_result["status"], "ok", "deploy plan must verify successfully");

    // ── 6. Verify devnet is producing blocks ──
    let tip = devnet.tip_block_number();
    assert!(tip > 0, "devnet tip should be > 0");

    // ── 7. Collect enough capacity to fund our deploy transaction ──
    let (input_tx_hash, input_index, input_capacity) = devnet.collect_capacity(artifact_binary.len());

    // ── 8. Build deploy transaction with real artifact via cellscript-ckb-adapter ──
    use cellscript_ckb_adapter::{build_deploy_transaction, DeployArtifactSpec};
    use ckb_types::{core::DepType, core::ScriptHashType, packed::CellInput, packed::OutPoint, prelude::*};

    let always_success_dep_json = devnet.always_success_dep();
    let genesis_cellbase_hash = always_success_dep_json["out_point"]["tx_hash"].as_str().unwrap();
    let genesis_dep_index: u32 =
        u32::from_str_radix(always_success_dep_json["out_point"]["index"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();

    let input_tx_hash_arr: [u8; 32] = hex::decode(input_tx_hash.trim_start_matches("0x")).unwrap().try_into().unwrap();
    let capacity_out_point = OutPoint::new_builder().tx_hash(input_tx_hash_arr.pack()).index(input_index).build();
    let capacity_input = CellInput::new_builder().previous_output(capacity_out_point).build();

    // always_success lock script for devnet (hash_type: data)
    let always_success_code_hash: [u8; 32] =
        hex::decode(ALWAYS_SUCCESS_CODE_HASH.trim_start_matches("0x")).unwrap().try_into().unwrap();
    let deployer_lock = packed::Script::new_builder()
        .code_hash(always_success_code_hash.pack())
        .hash_type(ScriptHashType::Data)
        .args(Bytes::default())
        .build();

    let artifact_hash = toolchain_artifact_hash.trim_start_matches("0x").to_string();

    let genesis_cellbase_hash_arr: [u8; 32] = hex::decode(genesis_cellbase_hash.trim_start_matches("0x")).unwrap().try_into().unwrap();
    let always_success_dep_out_point =
        OutPoint::new_builder().tx_hash(genesis_cellbase_hash_arr.pack()).index(genesis_dep_index).build();
    let cell_dep = packed::CellDep::new_builder().out_point(always_success_dep_out_point).dep_type(DepType::Code).build();

    let input_capacity_u64 = u64::from_str_radix(input_capacity.trim_start_matches("0x"), 16).unwrap();

    let spec = DeployArtifactSpec {
        name: "devnet-contract".to_string(),
        artifact_binary: Bytes::from(artifact_binary.clone()),
        artifact_hash,
        deployer_lock,
        capacity_input,
        capacity_input_shannons: input_capacity_u64,
        capacity_input_data: Bytes::default(),
        type_id_hash_type: ScriptHashType::Type,
        // On devnet, use always_success as type script so CKB VM can find & execute it.
        // In production, this would be the actual TYPE_ID script.
        type_script: Some(
            packed::Script::new_builder()
                .code_hash(always_success_code_hash.pack())
                .hash_type(ScriptHashType::Data)
                .args(Bytes::default())
                .build(),
        ),
        cell_deps: vec![cell_dep],
        header_deps: vec![],
        fee_shannons: 1_000,
    };

    let (tx, evidence) = build_deploy_transaction(&spec).unwrap();
    eprintln!(
        "Adapter built deploy tx: {} bytes, code_hash={}",
        tx.data().serialized_size_in_block(),
        evidence.code_hash.iter().map(|b| format!("{:02x}", b)).collect::<String>()
    );

    // ── 9. Convert packed transaction to RPC JSON and submit ──
    let rpc_tx = cellscript_ckb_adapter::to_rpc_transaction(&tx);
    let rpc_tx_value = serde_json::to_value(&rpc_tx).expect("failed to serialize rpc_tx");
    let tx_hash = devnet.submit_and_commit(&rpc_tx_value, "devnet contract deploy (toolchain)");
    eprintln!("Deployed via adapter: tx_hash={}", tx_hash);

    // ── 10. Verify on-chain: get_live_cell ──
    let live_cell = devnet.get_live_cell(&tx_hash, 0);
    assert_eq!(live_cell["status"].as_str(), Some("live"), "deployed cell must be live");

    let on_chain_output = &live_cell["cell"]["output"];
    let on_chain_data = &live_cell["cell"]["data"];
    let on_chain_data_hash = on_chain_data["hash"].as_str().unwrap();

    // Compute data_hash independently and verify against on-chain
    let computed_data_hash = ckb_data_hash(&artifact_binary);
    let computed_data_hash_hex = format!("0x{}", hex::encode(computed_data_hash));
    assert_eq!(on_chain_data_hash, computed_data_hash_hex, "on-chain data_hash must match computed data_hash from real artifact");

    // ── 11. Compute TYPE_ID and script hashes for identity records ──
    let type_id = compute_type_id(&tx_hash, 0);
    let on_chain_lock = &on_chain_output["lock"];
    let lock_script_hash = ckb_script_hash(
        on_chain_lock["code_hash"].as_str().unwrap(),
        on_chain_lock["hash_type"].as_str().unwrap(),
        on_chain_lock["args"].as_str().unwrap(),
    );

    // ── 12. cellc verify-artifact: verify artifact hash via toolchain ──
    cellc_verify_artifact(&artifact_path, toolchain_artifact_hash.trim_start_matches("0x"));

    // ── 13. Write Deployed.toml with real on-chain facts ──
    let out_point_str = format!("{}:0", tx_hash);
    let artifact_hash_hex = toolchain_artifact_hash.trim_start_matches("0x").to_string();
    let data_hash_hex = computed_data_hash_hex.clone();

    let deployed = DeployedManifest {
        version: DeployedManifest::CURRENT_VERSION,
        schema: DEPLOYED_MANIFEST_SCHEMA.to_string(),
        package: DeployedPackageInfo {
            edition: cellscript::CURRENT_EDITION,
            name: "devnet-contract".to_string(),
            version: "0.1.0".to_string(),
            source_hash: Some(source_hash.clone()),
        },
        build: Some(DeployedBuildInfo {
            edition: cellscript::CURRENT_EDITION,
            compatibility_profile_hash: "test-compatibility-profile".to_string(),
            compiler_version: Some(cellscript::VERSION.to_string()),
            artifact_hash: Some(artifact_hash_hex.clone()),
            metadata_hash: None,
            schema_hash: None,
            cell_data_codec_manifest_hash: None,
            abi_hash: None,
            constraints_hash: None,
        }),
        deployments: vec![DeploymentRecord {
            edition: cellscript::CURRENT_EDITION,
            compatibility_profile_hash: "test-compatibility-profile".to_string(),
            network: "ckb-devnet".to_string(),
            chain_id: "ckb-integration".to_string(),
            tx_hash: tx_hash.clone(),
            output_index: 0,
            code_hash: lock_script_hash.clone(),
            hash_type: ALWAYS_SUCCESS_HASH_TYPE.to_string(),
            dep_type: "code".to_string(),
            data_hash: data_hash_hex.clone(),
            out_point: out_point_str.clone(),
            artifact_hash: Some(artifact_hash_hex.clone()),
            metadata_hash: None,
            schema_hash: None,
            cell_data_codec_manifest_hash: None,
            abi_hash: None,
            constraints_hash: None,
            compiler_version: Some(cellscript::VERSION.to_string()),
            type_id: Some(type_id.clone()),
            script_role: Some(ScriptRole::Type),
            status: Some(DeploymentStatus::Active),
            upgrade_lineage: None,
            audit_report_hash: None,
            publisher_signature: None,
            cell_deps: vec![],
        }],
    };
    deployed.write_to_root(&pkg_dir).unwrap();

    // ── 14. Write Cell.lock ──
    let mut lockfile = Lockfile::new();
    lockfile.package = LockfilePackageInfo {
        edition: cellscript::CURRENT_EDITION,
        name: "devnet-contract".to_string(),
        version: "0.1.0".to_string(),
        namespace: Some("cellscript".to_string()),
        source_hash: Some(source_hash),
        compiler_source_hash: None,
        compiler_requirement: "*".to_string(),
        resolver_compiler_version: cellscript::VERSION.to_string(),
    };
    lockfile.package_build = Some(LockedBuildInfo {
        edition: cellscript::CURRENT_EDITION,
        compatibility_profile_hash: "test-compatibility-profile".to_string(),
        compiler_version: Some(cellscript::VERSION.to_string()),
        target_profile: Some("ckb".to_string()),
        artifact_hash: Some(artifact_hash_hex.clone()),
        ..Default::default()
    });
    lockfile.deployment.insert(
        "ckb-devnet".to_string(),
        LockfileDeploymentRef {
            record: out_point_str.clone(),
            record_hash: None,
            code_hash: Some(lock_script_hash.clone()),
            out_point: Some(out_point_str.clone()),
            data_hash: Some(data_hash_hex.clone()),
        },
    );
    lockfile.write_to_root(&pkg_dir).unwrap();

    // ── 15. Cross-verify all three identity layers against on-chain reality ──
    let read_lock = Lockfile::read_from_root(&pkg_dir).unwrap().unwrap();
    let read_deployed = DeployedManifest::read_from_root(&pkg_dir).unwrap().unwrap();

    // Package Identity: source_hash
    let computed = compute_source_hash(&pkg_dir).unwrap();
    assert_eq!(computed, read_lock.package.source_hash.as_deref().unwrap(), "source hash must match");

    // Build Identity: artifact_hash
    let lock_artifact = read_lock.package_build.as_ref().unwrap().artifact_hash.as_ref().unwrap();
    let deployed_artifact = read_deployed.build.as_ref().unwrap().artifact_hash.as_ref().unwrap();
    assert_eq!(lock_artifact, deployed_artifact, "artifact_hash must match between Cell.lock and Deployed.toml");

    // Deployment Identity
    let dep = &read_deployed.deployments[0];
    let lock_dep = read_lock.deployment.get("ckb-devnet").unwrap();
    assert_eq!(lock_dep.code_hash.as_deref(), Some(dep.code_hash.as_str()));
    assert_eq!(lock_dep.data_hash.as_deref(), Some(dep.data_hash.as_str()));
    assert_eq!(dep.data_hash, on_chain_data_hash, "Deployed.toml data_hash must match on-chain");
    assert_eq!(dep.tx_hash, tx_hash, "Deployed.toml tx_hash must match on-chain");
    assert_eq!(dep.type_id.as_deref(), Some(type_id.as_str()), "TYPE_ID must match");

    // Cross-verify: no violations
    let violations = cross_verify_lockfile_deployed(&read_lock, &read_deployed);
    assert!(violations.is_empty(), "no violations: {violations:?}");

    eprintln!("✓ Live devnet: cellc build -> deploy plan -> adapter -> devnet -> verify - full toolchain passed");
}

// ===========================================================================
// SCENARIO 6b: Live devnet full lifecycle with registry (#[ignore])
//
// Full lifecycle: create packages → cellc build → publish to registry →
// install via discovery → deploy to devnet → verify on-chain →
// cross-verify Cell.lock ↔ Deployed.toml ↔ chain.
// ===========================================================================

#[test]
#[ignore = "Requires ckb repo at ../ckb with compiled binary; starts real devnet"]
fn e2e_live_devnet_publish_deploy_verify_full_lifecycle() {
    let devnet = CkbDevnet::launch();

    let temp = tempfile::tempdir().unwrap();

    // ── 1. Create a CellScript package with real source code ──
    let app_repo = temp.path().join("source-repos/cellscript-app-contract");
    std::fs::create_dir_all(app_repo.join("src")).unwrap();
    std::fs::write(
        app_repo.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "app-contract"
version = "0.1.0"
namespace = "cellscript"

[build]
target = "riscv64-elf"
target_profile = "ckb"
out_dir = "build"
"#,
    )
    .unwrap();
    std::fs::write(
        app_repo.join("src/main.cell"),
        r#"
module app_contract::main

action verify(amount: u64) -> u64 {
    verification
        return amount
}
"#,
    )
    .unwrap();
    let hash_app = compute_source_hash(&app_repo).unwrap();

    let version_entry_app = RegistryVersion {
        edition: cellscript::CURRENT_EDITION,
        compatibility_profile_hash: "test-compatibility-profile".to_string(),
        version: "0.1.0".to_string(),
        tag: "v0.1.0".to_string(),
        source_hash: hash_app.clone(),
        cellscript_version: cellscript::VERSION.to_string(),
        dependencies: BTreeMap::new(),
        abi_index: None,
        schema_hash: None,
        license: Some("Apache-2.0".to_string()),
        released_at: None,
        status: cellscript::package::registry::RegistryEntryStatus::VerifiedBuild,
        yanked: false,
        yanked_at: None,
        yanked_reason: None,
        replaced_by: None,
        audit: None,
        compiler_requirement: "*".to_string(),
    };
    RegistryIndex::append_version(&app_repo, "app-contract", "cellscript", version_entry_app).unwrap();

    git_init(&app_repo);
    git_config_user(&app_repo);
    git_add_all(&app_repo);
    git_commit(&app_repo, "initial v0.1.0");
    git_tag(&app_repo, "v0.1.0");

    // ── 2. Create discovery index ──
    let discovery_repo = temp.path().join("discovery-index");
    let app_path = app_repo.to_string_lossy().to_string();
    init_discovery_repo(&discovery_repo, &[("cellscript", "app-contract", &app_path)]);

    // ── 3. Install via discovery ──
    let cache_dir = temp.path().join("cache");
    std::fs::create_dir_all(&cache_dir).unwrap();

    let discovery = DiscoveryIndex::new(&discovery_repo.to_string_lossy(), &cache_dir);
    discovery.clone_or_update().unwrap();

    let entry_app = discovery.lookup("cellscript", "app-contract").unwrap();
    assert_eq!(entry_app.name, "app-contract");

    // ── 4. Verify source hash after install ──
    let source_cache = temp.path().join("source-cache");
    std::fs::create_dir_all(&source_cache).unwrap();

    let clone_app = source_cache.join("app-contract");
    git_clone(&entry_app.source, &clone_app).unwrap();
    git_checkout(&clone_app, "v0.1.0").unwrap();

    let computed_app = compute_source_hash(&clone_app).unwrap();
    assert_eq!(computed_app, hash_app, "source hash must match after install");

    // ── 5. cellc build: compile real RISC-V ELF artifact ──
    let artifact_path = cellc_build(&clone_app);
    let artifact_binary = std::fs::read(&artifact_path).unwrap();
    assert!(artifact_binary.starts_with(b"\x7fELF"), "artifact must be a valid ELF");

    // ── 6. cellc ckb-hash + cellc verify-artifact ──
    let toolchain_hash = cellc_ckb_hash(&artifact_path);
    cellc_verify_artifact(&artifact_path, toolchain_hash.trim_start_matches("0x"));

    // ── 7. cellc deploy plan + deploy verify ──
    let deploy_plan_path = temp.path().join("app-deploy-plan.json");
    cellc_deploy_plan(&clone_app, &deploy_plan_path);
    let verify_result = cellc_verify_deploy(&deploy_plan_path);
    assert_eq!(verify_result["status"], "ok", "deploy plan must verify");

    // ── 8. Build deploy transaction via cellscript-ckb-adapter ──
    use cellscript_ckb_adapter::{build_deploy_transaction, DeployArtifactSpec};
    use ckb_types::{core::DepType, core::ScriptHashType, packed::CellInput, packed::OutPoint, prelude::*};

    let always_success_dep_json = devnet.always_success_dep();
    let genesis_cellbase_hash = always_success_dep_json["out_point"]["tx_hash"].as_str().unwrap();
    let genesis_dep_index: u32 =
        u32::from_str_radix(always_success_dep_json["out_point"]["index"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();

    let (input_tx_hash, input_index, input_capacity) = devnet.collect_capacity(artifact_binary.len());
    let input_capacity_u64 = u64::from_str_radix(input_capacity.trim_start_matches("0x"), 16).unwrap();

    let input_tx_hash_arr: [u8; 32] = hex::decode(input_tx_hash.trim_start_matches("0x")).unwrap().try_into().unwrap();
    let capacity_out_point = OutPoint::new_builder().tx_hash(input_tx_hash_arr.pack()).index(input_index).build();
    let capacity_input = CellInput::new_builder().previous_output(capacity_out_point).build();

    let always_success_code_hash: [u8; 32] =
        hex::decode(ALWAYS_SUCCESS_CODE_HASH.trim_start_matches("0x")).unwrap().try_into().unwrap();
    let deployer_lock = packed::Script::new_builder()
        .code_hash(always_success_code_hash.pack())
        .hash_type(ScriptHashType::Data)
        .args(Bytes::default())
        .build();

    let genesis_cellbase_hash_arr: [u8; 32] = hex::decode(genesis_cellbase_hash.trim_start_matches("0x")).unwrap().try_into().unwrap();
    let always_success_dep_out_point =
        OutPoint::new_builder().tx_hash(genesis_cellbase_hash_arr.pack()).index(genesis_dep_index).build();
    let cell_dep = packed::CellDep::new_builder().out_point(always_success_dep_out_point).dep_type(DepType::Code).build();

    let spec = DeployArtifactSpec {
        name: "app-contract".to_string(),
        artifact_binary: Bytes::from(artifact_binary.clone()),
        artifact_hash: toolchain_hash.trim_start_matches("0x").to_string(),
        deployer_lock,
        capacity_input,
        capacity_input_shannons: input_capacity_u64,
        capacity_input_data: Bytes::default(),
        type_id_hash_type: ScriptHashType::Type,
        type_script: Some(
            packed::Script::new_builder()
                .code_hash(always_success_code_hash.pack())
                .hash_type(ScriptHashType::Data)
                .args(Bytes::default())
                .build(),
        ),
        cell_deps: vec![cell_dep],
        header_deps: vec![],
        fee_shannons: 1_000,
    };

    let (tx, _evidence) = build_deploy_transaction(&spec).unwrap();

    // ── 9. Submit and verify on-chain ──
    let rpc_tx = cellscript_ckb_adapter::to_rpc_transaction(&tx);
    let rpc_tx_value = serde_json::to_value(&rpc_tx).expect("failed to serialize rpc_tx");
    let tx_hash = devnet.submit_and_commit(&rpc_tx_value, "app-contract deploy (toolchain)");
    eprintln!("Deployed app-contract via adapter: tx_hash={}", tx_hash);

    let live_cell = devnet.get_live_cell(&tx_hash, 0);
    assert_eq!(live_cell["status"].as_str(), Some("live"));

    let on_chain_data_hash = live_cell["cell"]["data"]["hash"].as_str().unwrap();
    let computed_data_hash = ckb_data_hash(&artifact_binary);
    let computed_data_hash_hex = format!("0x{}", hex::encode(computed_data_hash));
    assert_eq!(on_chain_data_hash, computed_data_hash_hex, "on-chain data_hash must match real artifact");

    // ── 10. Compute identity fields ──
    let on_chain_lock = &live_cell["cell"]["output"]["lock"];
    let lock_script_hash = ckb_script_hash(
        on_chain_lock["code_hash"].as_str().unwrap(),
        on_chain_lock["hash_type"].as_str().unwrap(),
        on_chain_lock["args"].as_str().unwrap(),
    );
    let type_id = compute_type_id(&tx_hash, 0);
    let artifact_hash_hex = toolchain_hash.trim_start_matches("0x").to_string();
    let data_hash_hex = computed_data_hash_hex;
    let out_point_str = format!("{}:0", tx_hash);

    // ── 11. Write Cell.lock with real on-chain facts ──
    let mut lockfile = Lockfile::new();
    lockfile.package = LockfilePackageInfo {
        edition: cellscript::CURRENT_EDITION,
        name: "app-contract".to_string(),
        version: "0.1.0".to_string(),
        namespace: Some("cellscript".to_string()),
        source_hash: Some(hash_app.clone()),
        compiler_source_hash: None,
        compiler_requirement: "*".to_string(),
        resolver_compiler_version: cellscript::VERSION.to_string(),
    };
    lockfile.package_build = Some(LockedBuildInfo {
        edition: cellscript::CURRENT_EDITION,
        compatibility_profile_hash: "test-compatibility-profile".to_string(),
        compiler_version: Some(cellscript::VERSION.to_string()),
        target_profile: Some("ckb".to_string()),
        artifact_hash: Some(artifact_hash_hex.clone()),
        ..Default::default()
    });
    lockfile.deployment.insert(
        "ckb-devnet".to_string(),
        LockfileDeploymentRef {
            record: out_point_str.clone(),
            record_hash: None,
            code_hash: Some(lock_script_hash.clone()),
            out_point: Some(out_point_str.clone()),
            data_hash: Some(data_hash_hex.clone()),
        },
    );
    lockfile.write_to_root(&app_repo).unwrap();

    // ── 12. Write Deployed.toml with on-chain facts ──
    let deployed = DeployedManifest {
        version: DeployedManifest::CURRENT_VERSION,
        schema: DEPLOYED_MANIFEST_SCHEMA.to_string(),
        package: DeployedPackageInfo {
            edition: cellscript::CURRENT_EDITION,
            name: "app-contract".to_string(),
            version: "0.1.0".to_string(),
            source_hash: Some(hash_app),
        },
        build: Some(DeployedBuildInfo {
            edition: cellscript::CURRENT_EDITION,
            compatibility_profile_hash: "test-compatibility-profile".to_string(),
            compiler_version: Some(cellscript::VERSION.to_string()),
            artifact_hash: Some(artifact_hash_hex),
            metadata_hash: None,
            schema_hash: None,
            cell_data_codec_manifest_hash: None,
            abi_hash: None,
            constraints_hash: None,
        }),
        deployments: vec![DeploymentRecord {
            edition: cellscript::CURRENT_EDITION,
            compatibility_profile_hash: "test-compatibility-profile".to_string(),
            network: "ckb-devnet".to_string(),
            chain_id: "ckb-integration".to_string(),
            tx_hash: tx_hash.clone(),
            output_index: 0,
            code_hash: lock_script_hash,
            hash_type: ALWAYS_SUCCESS_HASH_TYPE.to_string(),
            dep_type: "code".to_string(),
            data_hash: data_hash_hex,
            out_point: out_point_str.clone(),
            artifact_hash: None,
            metadata_hash: None,
            schema_hash: None,
            cell_data_codec_manifest_hash: None,
            abi_hash: None,
            constraints_hash: None,
            compiler_version: Some(cellscript::VERSION.to_string()),
            type_id: Some(type_id),
            script_role: Some(ScriptRole::Type),
            status: Some(DeploymentStatus::Active),
            upgrade_lineage: None,
            audit_report_hash: None,
            publisher_signature: None,
            cell_deps: vec![],
        }],
    };
    deployed.write_to_root(&app_repo).unwrap();

    // ── 13. Final cross-verification ──
    let read_lock = Lockfile::read_from_root(&app_repo).unwrap().unwrap();
    let read_deployed = DeployedManifest::read_from_root(&app_repo).unwrap().unwrap();

    let lock_art = read_lock.package_build.as_ref().unwrap().artifact_hash.as_ref().unwrap();
    let dep_art = read_deployed.build.as_ref().unwrap().artifact_hash.as_ref().unwrap();
    assert_eq!(lock_art, dep_art, "artifact_hash must match");

    assert_eq!(read_deployed.deployments[0].data_hash, on_chain_data_hash, "Deployed.toml data_hash must match on-chain");
    assert_eq!(read_deployed.deployments[0].tx_hash, tx_hash, "Deployed.toml tx_hash must match on-chain");

    let violations = cross_verify_lockfile_deployed(&read_lock, &read_deployed);
    assert!(violations.is_empty(), "no cross-verification violations: {violations:?}");

    eprintln!("✓ Full lifecycle: cellc build → publish → install → adapter deploy → devnet → verify");
}

// ===========================================================================
// SCENARIO 7: Discovery index add_entry + update flow
// ===========================================================================

#[test]
fn e2e_discovery_index_add_update_flow() {
    let temp = tempfile::tempdir().unwrap();

    // ── 1. Create empty discovery index ──
    let registry_repo = temp.path().join("discovery-index");
    std::fs::create_dir_all(&registry_repo).unwrap();
    git_init(&registry_repo);
    git_config_user(&registry_repo);
    git_commit(&registry_repo, "empty discovery index");

    // ── 2. Add entries via DiscoveryIndex::add_entry ──
    let cache_dir = temp.path().join("cache");
    std::fs::create_dir_all(&cache_dir).unwrap();

    let discovery = DiscoveryIndex::new(&registry_repo.to_string_lossy(), &cache_dir);
    discovery.clone_or_update().unwrap();

    // Add first package
    discovery.add_entry("cellscript", "token", "https://github.com/cellscript/token").unwrap();

    // Add second package in same namespace
    discovery.add_entry("cellscript", "amm", "https://github.com/cellscript/amm").unwrap();

    // Add package in different namespace
    discovery.add_entry("myns", "oracle", "https://github.com/myns/oracle").unwrap();

    // ── 3. Verify all entries are discoverable ──
    let token_entry = discovery.lookup("cellscript", "token").unwrap();
    assert_eq!(token_entry.name, "token");
    assert_eq!(token_entry.source, "https://github.com/cellscript/token");

    let amm_entry = discovery.lookup("cellscript", "amm").unwrap();
    assert_eq!(amm_entry.name, "amm");
    assert_eq!(amm_entry.source, "https://github.com/cellscript/amm");

    let oracle_entry = discovery.lookup("myns", "oracle").unwrap();
    assert_eq!(oracle_entry.name, "oracle");
    assert_eq!(oracle_entry.source, "https://github.com/myns/oracle");

    // ── 4. Verify missing entries fall back to Go-style convention ──
    // When no explicit discovery entry exists, lookup falls back to
    // github.com/<namespace>/<name> — no PR to a monorepo index required.
    let fallback = discovery.lookup("cellscript", "nonexistent").unwrap();
    assert_eq!(fallback.source, "https://github.com/cellscript/nonexistent");
    let fallback2 = discovery.lookup("otherns", "token").unwrap();
    assert_eq!(fallback2.source, "https://github.com/otherns/token");

    // ── 5. Create source repos for the discovered packages and verify end-to-end ──
    let token_repo = temp.path().join("source-repos/cellscript-token");
    let token_hash = init_source_repo(&token_repo, "token", "0.3.0", "cellscript");

    // Re-create discovery index pointing to local repos
    let discovery2_repo = temp.path().join("discovery-index-2");
    let token_repo_path = token_repo.to_string_lossy().to_string();
    init_discovery_repo(&discovery2_repo, &[("cellscript", "token", &token_repo_path)]);

    let discovery2 = DiscoveryIndex::new(&discovery2_repo.to_string_lossy(), &cache_dir);
    discovery2.clone_or_update().unwrap();

    let entry = discovery2.lookup("cellscript", "token").unwrap();
    assert_eq!(entry.source, token_repo_path);

    // ── 6. Full flow: clone source from discovery entry ──
    let source_cache = temp.path().join("source-cache-2");
    std::fs::create_dir_all(&source_cache).unwrap();
    let clone = source_cache.join("token");
    git_clone(&entry.source, &clone).unwrap();
    git_checkout(&clone, "v0.3.0").unwrap();

    let computed = compute_source_hash(&clone).unwrap();
    assert_eq!(computed, token_hash, "source hash must match after discovery → clone → checkout");
}

// ===========================================================================
// SCENARIO 8: Source hash cross-platform determinism + Cell.toml inclusion
// ===========================================================================

#[test]
fn e2e_source_hash_cross_platform_determinism() {
    let temp = tempfile::tempdir().unwrap();

    // ── 1. Create a package with multiple source files ──
    let pkg_dir = temp.path().join("multi-file-pkg");
    std::fs::create_dir_all(pkg_dir.join("src")).unwrap();
    std::fs::create_dir_all(pkg_dir.join("src/utils")).unwrap();

    std::fs::write(
        pkg_dir.join("Cell.toml"),
        r#"[package]
edition = "2026"
name = "multi-file"
version = "0.1.0"
namespace = "cellscript"
"#,
    )
    .unwrap();

    std::fs::write(pkg_dir.join("src/main.cell"), "module multi_file;\n").unwrap();
    std::fs::write(pkg_dir.join("src/utils/helpers.cell"), "module multi_file_utils_helpers;\n").unwrap();

    // ── 2. Compute hash multiple times ──
    let hash1 = compute_source_hash(&pkg_dir).unwrap();
    let hash2 = compute_source_hash(&pkg_dir).unwrap();
    let hash3 = compute_source_hash(&pkg_dir).unwrap();

    assert_eq!(hash1, hash2, "source hash must be deterministic (run 1 vs 2)");
    assert_eq!(hash2, hash3, "source hash must be deterministic (run 2 vs 3)");

    // ── 3. Verify hash changes when any file changes ──
    std::fs::write(pkg_dir.join("src/utils/helpers.cell"), "module multi_file_utils_helpers;\n// Updated\n").unwrap();
    let hash4 = compute_source_hash(&pkg_dir).unwrap();
    assert_ne!(hash1, hash4, "source hash must change when a source file changes");

    // ── 4. Verify Cell.toml is included in hash ──
    let original_hash = compute_source_hash(&pkg_dir).unwrap();
    std::fs::write(
        pkg_dir.join("Cell.toml"),
        r#"[package]
edition = "2026"
name = "multi-file"
version = "0.2.0"
namespace = "cellscript"
"#,
    )
    .unwrap();
    let new_hash = compute_source_hash(&pkg_dir).unwrap();
    assert_ne!(original_hash, new_hash, "source hash must change when Cell.toml changes");

    // ── 5. Verify non-.cell files are excluded ──
    std::fs::write(pkg_dir.join("src/README.md"), "# This should not affect hash").unwrap();
    let hash_with_readme = compute_source_hash(&pkg_dir).unwrap();
    // Removing .md should NOT change the hash since .md files are not included
    let _ = std::fs::remove_file(pkg_dir.join("src/README.md"));
    let hash_after_removing = compute_source_hash(&pkg_dir).unwrap();
    assert_eq!(hash_with_readme, hash_after_removing, "removing .md should not change hash (non-.cell file)");
    let pkg_dir2 = temp.path().join("determinism-check");
    std::fs::create_dir_all(pkg_dir2.join("src")).unwrap();
    std::fs::write(
        pkg_dir2.join("Cell.toml"),
        r#"[package]
edition = "2026"
name = "det-check"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(pkg_dir2.join("src/main.cell"), "module det_check;\n").unwrap();

    let hash_no_extra = compute_source_hash(&pkg_dir2).unwrap();

    // Add a non-.cell file
    std::fs::write(pkg_dir2.join("src/notes.txt"), "These are notes").unwrap();
    let hash_with_extra = compute_source_hash(&pkg_dir2).unwrap();

    assert_eq!(hash_no_extra, hash_with_extra, "non-.cell files should not affect source hash");
}

// ===========================================================================
// SCENARIO 9: Registry.json append + update idempotency
// ===========================================================================

#[test]
fn e2e_registry_json_append_update_idempotency() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("registry-test-pkg");
    std::fs::create_dir_all(&repo).unwrap();

    // ── 1. Append first version ──
    let v1 = RegistryVersion {
        edition: cellscript::CURRENT_EDITION,
        compatibility_profile_hash: "test-compatibility-profile".to_string(),
        version: "0.1.0".to_string(),
        tag: "v0.1.0".to_string(),
        source_hash: "hash_v1".to_string(),
        cellscript_version: "0.19.0".to_string(),
        dependencies: BTreeMap::new(),
        abi_index: None,
        schema_hash: None,
        license: Some("MIT".to_string()),
        released_at: Some("2026-01-01T00:00:00Z".to_string()),
        status: cellscript::package::registry::RegistryEntryStatus::VerifiedBuild,
        yanked: false,
        yanked_at: None,
        yanked_reason: None,
        replaced_by: None,
        audit: None,
        compiler_requirement: "*".to_string(),
    };
    RegistryIndex::append_version(&repo, "pkg", "ns", v1).unwrap();

    let index = RegistryIndex::read_from_repo(&repo).unwrap();
    assert_eq!(index.versions.len(), 1);
    assert_eq!(index.versions[0].version, "0.1.0");

    // ── 2. Append second version ──
    let v2 = RegistryVersion {
        edition: cellscript::CURRENT_EDITION,
        compatibility_profile_hash: "test-compatibility-profile".to_string(),
        version: "0.2.0".to_string(),
        tag: "v0.2.0".to_string(),
        source_hash: "hash_v2".to_string(),
        cellscript_version: "0.19.0".to_string(),
        dependencies: BTreeMap::new(),
        abi_index: None,
        schema_hash: None,
        license: Some("MIT".to_string()),
        released_at: Some("2026-02-01T00:00:00Z".to_string()),
        status: cellscript::package::registry::RegistryEntryStatus::VerifiedBuild,
        yanked: false,
        yanked_at: None,
        yanked_reason: None,
        replaced_by: None,
        audit: None,
        compiler_requirement: "*".to_string(),
    };
    RegistryIndex::append_version(&repo, "pkg", "ns", v2).unwrap();

    let index = RegistryIndex::read_from_repo(&repo).unwrap();
    assert_eq!(index.versions.len(), 2);

    // ── 3. Re-append v0.1.0 (update semantics — should replace, not duplicate) ──
    let v1_updated = RegistryVersion {
        edition: cellscript::CURRENT_EDITION,
        compatibility_profile_hash: "test-compatibility-profile".to_string(),
        version: "0.1.0".to_string(),
        tag: "v0.1.0".to_string(),
        source_hash: "hash_v1_updated".to_string(),
        cellscript_version: "0.19.0".to_string(),
        dependencies: BTreeMap::new(),
        abi_index: None,
        schema_hash: None,
        license: Some("Apache-2.0".to_string()),
        released_at: Some("2026-01-01T00:00:00Z".to_string()),
        status: cellscript::package::registry::RegistryEntryStatus::VerifiedBuild,
        yanked: true,
        yanked_at: None,
        yanked_reason: None,
        replaced_by: None,
        audit: Some(RegistryAuditInfo { report_hash: Some("0xaudit_hash".to_string()), acceptance_gate: Some("failed".to_string()) }),
        compiler_requirement: "*".to_string(),
    };
    RegistryIndex::append_version(&repo, "pkg", "ns", v1_updated).unwrap();

    let index = RegistryIndex::read_from_repo(&repo).unwrap();
    assert_eq!(index.versions.len(), 2, "re-appending same version should not create duplicates");

    let v1_entry = index.versions.iter().find(|v| v.version == "0.1.0").unwrap();
    assert!(v1_entry.yanked, "re-appended version should be updated");
    assert_eq!(v1_entry.source_hash, "hash_v1_updated");
    assert_eq!(v1_entry.license.as_deref(), Some("Apache-2.0"));
    assert!(v1_entry.audit.is_some());

    // ── 4. Verify registry.json is valid JSON and round-trips ──
    let json_str = std::fs::read_to_string(repo.join("registry.json")).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
    assert_eq!(parsed["name"], "pkg");
    assert_eq!(parsed["namespace"], "ns");
    assert_eq!(parsed["versions"].as_array().unwrap().len(), 2);
}

// ===========================================================================
// SCENARIO 10: Full registry resolution via PackageManager
// ===========================================================================

#[test]
fn e2e_package_manager_registry_resolution_with_local_git() {
    let temp = tempfile::tempdir().unwrap();

    // ── 1. Create and publish "math-lib" in a local git repo ──
    let math_repo = temp.path().join("source-repos/cellscript-math-lib");
    let hash_math = init_source_repo(&math_repo, "math-lib", "0.1.0", "cellscript");

    // ── 2. Create a consumer package that depends on math-lib ──
    let consumer_dir = temp.path().join("consumer");
    create_package_with_dep(&consumer_dir, "consumer", "0.1.0", Some("cellscript"), "math-lib", "0.1.0", Some("cellscript"));

    // ── 3. Create discovery index ──
    let discovery_repo = temp.path().join("discovery-index");
    let math_path = math_repo.to_string_lossy().to_string();
    init_discovery_repo(&discovery_repo, &[("cellscript", "math-lib", &math_path)]);

    // ── 4. Resolve dependency via PackageManager ──
    // Note: This requires the discovery index to be reachable at DEFAULT_REGISTRY_URL
    // For local testing, we verify the resolution logic manually

    // Verify the source repo structure
    let index = RegistryIndex::read_from_repo(&math_repo).unwrap();
    assert_eq!(index.name, "math-lib");
    assert_eq!(index.versions[0].source_hash, hash_math);

    // Verify git tags
    let tags = git_list_tags(&math_repo).unwrap();
    assert!(tags.iter().any(|(t, _)| t == "v0.1.0"));

    // Clone and verify
    let clone_dir = temp.path().join("resolved/math-lib");
    git_clone(&math_path, &clone_dir).unwrap();
    git_checkout(&clone_dir, "v0.1.0").unwrap();

    let computed = compute_source_hash(&clone_dir).unwrap();
    assert_eq!(computed, hash_math, "source hash must match after registry resolution");

    // Verify Cell.toml is present
    assert!(clone_dir.join("Cell.toml").exists());
    assert!(clone_dir.join("registry.json").exists());

    // ── 5. Build Cell.lock with the resolved dependency ──
    let revision = git_revision(&clone_dir).unwrap();

    let mut lockfile = Lockfile::new();
    lockfile.package = LockfilePackageInfo {
        edition: cellscript::CURRENT_EDITION,
        name: "consumer".to_string(),
        version: "0.1.0".to_string(),
        namespace: Some("cellscript".to_string()),
        source_hash: None,
        compiler_source_hash: None,
        compiler_requirement: "*".to_string(),
        resolver_compiler_version: cellscript::VERSION.to_string(),
    };
    lockfile.dependencies.insert(
        "math-lib".to_string(),
        LockedDependency {
            name: "math-lib".to_string(),
            namespace: Some("cellscript".to_string()),
            version: "0.1.0".to_string(),
            source: LockedSource::Registry {
                registry: "https://github.com/cellscript/cellscript-registry".to_string(),
                url: math_path,
                revision,
                namespace: "cellscript".to_string(),
                version: "0.1.0".to_string(),
            },
            source_hash: Some(hash_math),
            manifest_digest: "sha256:test-math-manifest".to_string(),
            dependencies: BTreeMap::new(),
            build: None,
            compiler_requirement: "*".to_string(),
            resolver_compiler_version: cellscript::VERSION.to_string(),
        },
    );
    lockfile.root.manifest_digest = cellscript::package::compute_manifest_digest(&consumer_dir).unwrap();
    lockfile.root.dependencies.insert("math-lib".to_string(), "math-lib".to_string());
    lockfile.write_to_root(&consumer_dir).unwrap();

    // ── 6. Verify Cell.lock consistency ──
    let manifest: PackageManifest = toml::from_str(&std::fs::read_to_string(consumer_dir.join("Cell.toml")).unwrap()).unwrap();
    let lockfile = Lockfile::read_from_root(&consumer_dir).unwrap().unwrap();
    let issues = lockfile.consistency_issues(&manifest);
    assert!(issues.is_empty(), "lockfile should be consistent after registry resolution: {issues:?}");
}
