//! Integration tests for the Registry artifact model and offline index tools.
//!
//! Tests cover:
//! - Source hash computation determinism
//! - RegistryIndex read/write/append
//! - Discovery index lookup with local Git fixture
//! - Deployed.toml file round-trip
//! - Cell.lock new fields (package.build, deployment.*)
//! - Public artifact API dependency resolution with immutable snapshots
//! - Explicit offline Git fixture editing and verification
//! - Fail-closed verification on hash mismatch

use base64::Engine as _;
use cellscript::package::registry::{
    compute_source_hash, DiscoveryEntry, DiscoveryIndex, RegistryAuditInfo, RegistryDependencyRef, RegistryEntryStatus, RegistryIndex,
    RegistryVersion,
};
use cellscript::package::{
    DeployedBuildInfo, DeployedManifest, DeployedPackageInfo, DeploymentCellDep, DeploymentRecord, DeploymentStatus, LockedBuildInfo,
    LockedDependency, LockedSource, Lockfile, LockfileDeploymentRef, LockfilePackageInfo, PackageManager, ScriptRole,
    DEPLOYED_MANIFEST_SCHEMA,
};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

static REGISTRY_ENV_LOCK: Mutex<()> = Mutex::new(());

struct RegistryEnvGuard {
    previous: Option<OsString>,
    _guard: MutexGuard<'static, ()>,
}

impl RegistryEnvGuard {
    fn new(url: &str) -> Self {
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

struct PackageArtifactApi {
    origin: String,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Drop for PackageArtifactApi {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take()
            && let Err(payload) = handle.join()
            && !std::thread::panicking()
        {
            std::panic::resume_unwind(payload);
        }
    }
}

fn read_mock_http_path(stream: &mut std::net::TcpStream) -> String {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let read = match stream.read(&mut buffer) {
            Ok(read) => read,
            Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted) => {
                std::thread::yield_now();
                continue;
            }
            Err(error) => panic!("artifact API fixture request read failed: {error}"),
        };
        assert_ne!(read, 0, "artifact API request ended before headers");
        request.extend_from_slice(&buffer[..read]);
        if let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            let headers = String::from_utf8_lossy(&request[..header_end]);
            return headers.lines().next().and_then(|line| line.split_whitespace().nth(1)).unwrap_or("/").to_string();
        }
    }
}

fn start_package_artifact_api(source_root: &Path, verification_status: &str) -> PackageArtifactApi {
    let index = RegistryIndex::read_from_repo(source_root).unwrap();
    assert_eq!(index.versions.len(), 1, "single-package API fixture expects one release");
    let version = &index.versions[0];
    let snapshot_files = ["Cell.toml", "src/main.cell"]
        .into_iter()
        .map(|path| {
            let content = std::fs::read(source_root.join(path)).unwrap();
            serde_json::json!({
                "path": path,
                "blake2b256": hex::encode(cellscript::ckb_blake2b256(&content)),
                "content_base64": base64::engine::general_purpose::STANDARD.encode(content),
            })
        })
        .collect::<Vec<_>>();
    let snapshot = serde_json::to_vec(&serde_json::json!({
        "schema": "cellscript-source-snapshot-v1",
        "package": { "namespace": index.namespace, "name": index.name, "version": version.version },
        "files": snapshot_files,
    }))
    .unwrap();
    let snapshot_hash = format!("sha256:{}", hex::encode(Sha256::digest(&snapshot)));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let artifact_path = format!("/v1/artifacts/{}/{}", index.namespace, index.name);
    let snapshot_path = format!("/source-snapshots/{}/{}/{}/fixture.json", index.namespace, index.name, version.version);
    let artifact = serde_json::to_vec(&serde_json::json!({
        "schema": "cellscript-registry-artifact",
        "namespace": index.namespace,
        "name": index.name,
        "repository": format!("https://example.test/{}/{}", index.namespace, index.name),
        "artifact": {
            "kind": "source_library",
            "profile": "cellscript_source",
            "consumption_mode": "dependency",
            "language": "cellscript"
        },
        "releases": [{
            "release": version.version,
            "verification_status": verification_status,
            "availability_status": "active",
            "registry_entry": index,
            "immutable_bundle": {
                "schema": "cellscript-registry-immutable-bundle",
                "url": format!("{origin}{snapshot_path}"),
                "snapshot_hash": snapshot_hash,
                "source_hash": version.source_hash,
                "size_bytes": snapshot.len(),
                "content_type": "application/vnd.cellscript.source-snapshot+json"
            }
        }]
    }))
    .unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let server_stop = Arc::clone(&stop);
    let handle = std::thread::spawn(move || {
        while !server_stop.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let path = read_mock_http_path(&mut stream);
                    let (status, content_type, body) = if path == artifact_path {
                        ("200 OK", "application/json", artifact.as_slice())
                    } else if path == snapshot_path {
                        ("200 OK", "application/vnd.cellscript.source-snapshot+json", snapshot.as_slice())
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
    PackageArtifactApi { origin, stop, handle: Some(handle) }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn git_init(repo_dir: &Path) {
    let status = std::process::Command::new("git").args(["init"]).current_dir(repo_dir).status().expect("git init");
    assert!(status.success());
}

fn git_add_all(repo_dir: &Path) {
    let status = std::process::Command::new("git").args(["add", "."]).current_dir(repo_dir).status().expect("git add");
    assert!(status.success());
}

fn git_commit(repo_dir: &Path, msg: &str) {
    // Ensure there is at least one tracked file
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
    assert!(status.success());
}

fn git_tag(repo_dir: &Path, tag: &str) {
    let status = std::process::Command::new("git")
        .args(["-c", "tag.gpgSign=false", "tag", tag])
        .current_dir(repo_dir)
        .status()
        .expect("git tag");
    assert!(status.success());
}

/// Create a minimal CellScript package directory with Cell.toml and src/main.cell.
fn create_minimal_package(dir: &Path, name: &str, version: &str, namespace: Option<&str>) {
    std::fs::create_dir_all(dir.join("src")).unwrap();

    let mut toml = String::from("[package]\nedition = \"2026\"\n");
    toml.push_str(&format!("name = \"{}\"\n", name));
    toml.push_str(&format!("version = \"{}\"\n", version));
    if let Some(ns) = namespace {
        toml.push_str(&format!("namespace = \"{}\"\n", ns));
    }
    std::fs::write(dir.join("Cell.toml"), toml).unwrap();

    let cell = format!("module {};\n", name);
    std::fs::write(dir.join("src/main.cell"), cell).unwrap();
}

// ---------------------------------------------------------------------------
// Source hash computation
// ---------------------------------------------------------------------------

#[test]
fn compute_source_hash_is_deterministic() {
    let temp = tempfile::tempdir().unwrap();
    create_minimal_package(temp.path(), "hash-test", "0.1.0", None);

    let hash1 = compute_source_hash(temp.path()).unwrap();
    let hash2 = compute_source_hash(temp.path()).unwrap();
    assert_eq!(hash1, hash2, "source hash must be deterministic for identical content");
    assert!(!hash1.is_empty(), "source hash must not be empty");
}

#[test]
fn compute_source_hash_changes_when_source_changes() {
    let temp = tempfile::tempdir().unwrap();
    create_minimal_package(temp.path(), "hash-test", "0.1.0", None);

    let hash1 = compute_source_hash(temp.path()).unwrap();

    std::fs::write(temp.path().join("src/main.cell"), "module hash_test_updated;\n").unwrap();

    let hash2 = compute_source_hash(temp.path()).unwrap();
    assert_ne!(hash1, hash2, "source hash must change when source content changes");
}

#[test]
fn compute_source_hash_includes_cell_toml() {
    let temp = tempfile::tempdir().unwrap();
    create_minimal_package(temp.path(), "hash-test", "0.1.0", None);

    let hash1 = compute_source_hash(temp.path()).unwrap();

    let mut toml = String::from("[package]\n");
    toml.push_str("name = \"hash-test\"\n");
    toml.push_str("version = \"0.2.0\"\n");
    std::fs::write(temp.path().join("Cell.toml"), toml).unwrap();

    let hash2 = compute_source_hash(temp.path()).unwrap();
    assert_ne!(hash1, hash2, "source hash must change when Cell.toml changes");
}

#[test]
fn compute_source_hash_includes_configured_source_roots() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(temp.path().join("contracts")).unwrap();
    std::fs::write(
        temp.path().join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "hash-test"
version = "0.1.0"
entry = "contracts/main.cell"
source_roots = ["contracts"]
"#,
    )
    .unwrap();
    std::fs::write(temp.path().join("contracts/main.cell"), "module hash_test;\n").unwrap();

    let hash1 = compute_source_hash(temp.path()).unwrap();
    std::fs::write(temp.path().join("contracts/main.cell"), "module hash_test_updated;\n").unwrap();
    let hash2 = compute_source_hash(temp.path()).unwrap();

    assert_ne!(hash1, hash2, "source hash must cover configured package source_roots");
}

// ---------------------------------------------------------------------------
// RegistryIndex — read/write/append
// ---------------------------------------------------------------------------

#[test]
fn registry_index_write_read_round_trip() {
    let temp = tempfile::tempdir().unwrap();
    let index = RegistryIndex {
        schema_version: RegistryIndex::CURRENT_SCHEMA_VERSION,
        name: "token".to_string(),
        namespace: "cellscript".to_string(),
        versions: vec![RegistryVersion {
            edition: cellscript::CURRENT_EDITION,
            compatibility_profile_hash: "test-compatibility-profile".to_string(),
            version: "0.3.0".to_string(),
            tag: "v0.3.0".to_string(),
            source_hash: "abcd1234".to_string(),
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
        }],
    };

    index.write_to_repo(temp.path()).unwrap();
    let read_back = RegistryIndex::read_from_repo(temp.path()).unwrap();

    assert_eq!(read_back.schema_version, RegistryIndex::CURRENT_SCHEMA_VERSION);
    assert_eq!(read_back.name, "token");
    assert_eq!(read_back.namespace, "cellscript");
    assert_eq!(read_back.versions.len(), 1);
    assert_eq!(read_back.versions[0].version, "0.3.0");
    assert_eq!(read_back.versions[0].source_hash, "abcd1234");
    assert_eq!(read_back.versions[0].license.as_deref(), Some("MIT"));
}

#[test]
fn registry_index_append_version_creates_new_file() {
    let temp = tempfile::tempdir().unwrap();

    let version = RegistryVersion {
        edition: cellscript::CURRENT_EDITION,
        compatibility_profile_hash: "test-compatibility-profile".to_string(),
        version: "0.1.0".to_string(),
        tag: "v0.1.0".to_string(),
        source_hash: "hash_of_source".to_string(),
        cellscript_version: "0.19.0".to_string(),
        dependencies: BTreeMap::new(),
        abi_index: None,
        schema_hash: None,
        license: None,
        released_at: None,
        status: cellscript::package::registry::RegistryEntryStatus::VerifiedBuild,
        yanked: false,
        yanked_at: None,
        yanked_reason: None,
        replaced_by: None,
        audit: None,
        compiler_requirement: "*".to_string(),
    };

    RegistryIndex::append_version(temp.path(), "my_pkg", "my_ns", version).unwrap();

    let index = RegistryIndex::read_from_repo(temp.path()).unwrap();
    assert_eq!(index.name, "my_pkg");
    assert_eq!(index.namespace, "my_ns");
    assert_eq!(index.versions.len(), 1);
    assert_eq!(index.versions[0].version, "0.1.0");
}

#[test]
fn registry_index_append_version_updates_existing() {
    let temp = tempfile::tempdir().unwrap();

    let v1 = RegistryVersion {
        edition: cellscript::CURRENT_EDITION,
        compatibility_profile_hash: "test-compatibility-profile".to_string(),
        version: "0.1.0".to_string(),
        tag: "v0.1.0".to_string(),
        source_hash: "h1".to_string(),
        cellscript_version: "0.19.0".to_string(),
        dependencies: BTreeMap::new(),
        abi_index: None,
        schema_hash: None,
        license: None,
        released_at: None,
        status: cellscript::package::registry::RegistryEntryStatus::VerifiedBuild,
        yanked: false,
        yanked_at: None,
        yanked_reason: None,
        replaced_by: None,
        audit: None,
        compiler_requirement: "*".to_string(),
    };
    RegistryIndex::append_version(temp.path(), "pkg", "ns", v1).unwrap();

    let v2 = RegistryVersion {
        edition: cellscript::CURRENT_EDITION,
        compatibility_profile_hash: "test-compatibility-profile".to_string(),
        version: "0.2.0".to_string(),
        tag: "v0.2.0".to_string(),
        source_hash: "h2".to_string(),
        cellscript_version: "0.19.0".to_string(),
        dependencies: BTreeMap::new(),
        abi_index: None,
        schema_hash: None,
        license: None,
        released_at: None,
        status: cellscript::package::registry::RegistryEntryStatus::VerifiedBuild,
        yanked: false,
        yanked_at: None,
        yanked_reason: None,
        replaced_by: None,
        audit: None,
        compiler_requirement: "*".to_string(),
    };
    RegistryIndex::append_version(temp.path(), "pkg", "ns", v2).unwrap();

    let index = RegistryIndex::read_from_repo(temp.path()).unwrap();
    assert_eq!(index.versions.len(), 2);

    // Re-appending same version should update (not duplicate)
    let v1_updated = RegistryVersion {
        edition: cellscript::CURRENT_EDITION,
        compatibility_profile_hash: "test-compatibility-profile".to_string(),
        version: "0.1.0".to_string(),
        tag: "v0.1.0".to_string(),
        source_hash: "h1_updated".to_string(),
        cellscript_version: "0.19.0".to_string(),
        dependencies: BTreeMap::new(),
        abi_index: None,
        schema_hash: None,
        license: None,
        released_at: None,
        status: cellscript::package::registry::RegistryEntryStatus::VerifiedBuild,
        yanked: true,
        yanked_at: None,
        yanked_reason: None,
        replaced_by: None,
        audit: None,
        compiler_requirement: "*".to_string(),
    };
    RegistryIndex::append_version(temp.path(), "pkg", "ns", v1_updated).unwrap();

    let index = RegistryIndex::read_from_repo(temp.path()).unwrap();
    assert_eq!(index.versions.len(), 2, "re-appending same version should not create duplicates");
    let v1_entry = index.versions.iter().find(|v| v.version == "0.1.0").unwrap();
    assert!(v1_entry.yanked, "re-appended version should be updated (yanked = true)");
    assert_eq!(v1_entry.source_hash, "h1_updated");
}

#[test]
fn registry_index_with_dependencies_and_audit() {
    let temp = tempfile::tempdir().unwrap();

    let deps = BTreeMap::from([(
        "token".to_string(),
        RegistryDependencyRef { namespace: "cellscript".to_string(), version: "0.3.0".to_string() },
    )]);

    let version = RegistryVersion {
        edition: cellscript::CURRENT_EDITION,
        compatibility_profile_hash: "test-compatibility-profile".to_string(),
        version: "1.0.0".to_string(),
        tag: "v1.0.0".to_string(),
        source_hash: "deadbeef".to_string(),
        cellscript_version: "0.19.0".to_string(),
        dependencies: deps,
        abi_index: Some("0xabc".to_string()),
        schema_hash: Some("0xdef".to_string()),
        license: Some("Apache-2.0".to_string()),
        released_at: Some("2026-05-07T00:00:00Z".to_string()),
        status: cellscript::package::registry::RegistryEntryStatus::VerifiedBuild,
        yanked: false,
        yanked_at: None,
        yanked_reason: None,
        replaced_by: None,
        audit: Some(RegistryAuditInfo { report_hash: Some("0x5555".to_string()), acceptance_gate: Some("passed".to_string()) }),
        compiler_requirement: "*".to_string(),
    };

    RegistryIndex::append_version(temp.path(), "amm", "cellscript", version).unwrap();

    let index = RegistryIndex::read_from_repo(temp.path()).unwrap();
    let v = &index.versions[0];
    assert_eq!(v.dependencies.len(), 1);
    assert_eq!(v.dependencies["token"].namespace, "cellscript");
    assert_eq!(v.audit.as_ref().unwrap().acceptance_gate.as_deref(), Some("passed"));
}

// ---------------------------------------------------------------------------
// Discovery Index — local Git fixture
// ---------------------------------------------------------------------------

#[test]
fn discovery_index_lookup_with_local_git() {
    let temp = tempfile::tempdir().unwrap();
    let registry_dir = temp.path().join("registry-repo");
    std::fs::create_dir_all(&registry_dir).unwrap();

    git_init(&registry_dir);

    let ns_dir = registry_dir.join("cellscript");
    std::fs::create_dir_all(&ns_dir).unwrap();
    let entry = DiscoveryEntry {
        name: "token".to_string(),
        namespace: "cellscript".to_string(),
        source: "https://github.com/cellscript/token".to_string(),
    };
    let entry_json = serde_json::to_string_pretty(&entry).unwrap();
    std::fs::write(ns_dir.join("token.json"), entry_json).unwrap();

    git_add_all(&registry_dir);
    git_commit(&registry_dir, "initial registry entries");

    let cache_dir = temp.path().join("cache");
    std::fs::create_dir_all(&cache_dir).unwrap();

    let discovery = DiscoveryIndex::new(&registry_dir.to_string_lossy(), &cache_dir);
    let clone_dir = discovery.clone_or_update().unwrap();
    assert!(clone_dir.exists());

    let found = discovery.lookup("cellscript", "token").unwrap();
    assert_eq!(found.name, "token");
    assert_eq!(found.namespace, "cellscript");
    assert_eq!(found.source, "https://github.com/cellscript/token");
}

#[test]
fn discovery_index_lookup_missing_package_falls_back_to_convention() {
    let temp = tempfile::tempdir().unwrap();
    let registry_dir = temp.path().join("registry-repo");
    std::fs::create_dir_all(&registry_dir).unwrap();

    git_init(&registry_dir);
    git_commit(&registry_dir, "empty registry");

    let cache_dir = temp.path().join("cache");
    std::fs::create_dir_all(&cache_dir).unwrap();

    let discovery = DiscoveryIndex::new(&registry_dir.to_string_lossy(), &cache_dir);
    discovery.clone_or_update().unwrap();

    // When no explicit entry exists, lookup falls back to Go-style convention:
    // github.com/<namespace>/<name>. No PR to a monorepo discovery index required.
    let result = discovery.lookup("nonexistent", "nope").unwrap();
    assert_eq!(result.source, "https://github.com/nonexistent/nope");
    assert_eq!(result.namespace, "nonexistent");
    assert_eq!(result.name, "nope");
}

#[test]
fn discovery_index_add_entry() {
    let temp = tempfile::tempdir().unwrap();
    let registry_dir = temp.path().join("registry-repo");
    std::fs::create_dir_all(&registry_dir).unwrap();

    git_init(&registry_dir);
    git_commit(&registry_dir, "empty registry");

    let cache_dir = temp.path().join("cache");
    std::fs::create_dir_all(&cache_dir).unwrap();

    let discovery = DiscoveryIndex::new(&registry_dir.to_string_lossy(), &cache_dir);
    discovery.clone_or_update().unwrap();

    let entry_path = discovery.add_entry("myns", "mypkg", "https://github.com/myns/mypkg").unwrap();
    assert!(entry_path.ends_with("myns/mypkg.json"), "unexpected entry path: {}", entry_path.display());
    assert!(entry_path.exists(), "registry add should write the entry file");

    let found = discovery.lookup("myns", "mypkg").unwrap();
    assert_eq!(found.name, "mypkg");
    assert_eq!(found.namespace, "myns");
    assert_eq!(found.source, "https://github.com/myns/mypkg");
}

// ---------------------------------------------------------------------------
// Deployed.toml — file round-trip
// ---------------------------------------------------------------------------

#[test]
fn deployed_manifest_file_round_trip() {
    let temp = tempfile::tempdir().unwrap();

    let manifest = DeployedManifest {
        version: DeployedManifest::CURRENT_VERSION,
        schema: DEPLOYED_MANIFEST_SCHEMA.to_string(),
        package: DeployedPackageInfo {
            edition: cellscript::CURRENT_EDITION,
            name: "token".to_string(),
            version: "1.0.0".to_string(),
            source_hash: Some("blake2b:0xabc".to_string()),
        },
        build: Some(DeployedBuildInfo {
            edition: cellscript::CURRENT_EDITION,
            compatibility_profile_hash: "test-compatibility-profile".to_string(),
            compiler_version: Some("0.19.0".to_string()),
            artifact_hash: Some("blake2b:0xdef".to_string()),
            metadata_hash: None,
            schema_hash: Some("blake2b:0x999".to_string()),
            cell_data_codec_manifest_hash: None,
            abi_hash: None,
            constraints_hash: None,
        }),
        deployments: vec![DeploymentRecord {
            edition: cellscript::CURRENT_EDITION,
            compatibility_profile_hash: "test-compatibility-profile".to_string(),
            network: "aggron4".to_string(),
            chain_id: "ckb-testnet".to_string(),
            tx_hash: "0xaaaa1111".to_string(),
            output_index: 0,
            code_hash: "0xbbbb2222".to_string(),
            hash_type: "data1".to_string(),
            dep_type: "code".to_string(),
            data_hash: "0xcccc3333".to_string(),
            out_point: "0xaaaa1111:0".to_string(),
            artifact_hash: Some("blake2b:0xdef".to_string()),
            metadata_hash: None,
            schema_hash: Some("blake2b:0x999".to_string()),
            cell_data_codec_manifest_hash: None,
            abi_hash: None,
            constraints_hash: None,
            compiler_version: Some("0.19.0".to_string()),
            type_id: None,
            script_role: Some(ScriptRole::Lock),
            status: Some(DeploymentStatus::Active),
            upgrade_lineage: None,
            audit_report_hash: None,
            publisher_signature: None,
            cell_deps: vec![DeploymentCellDep {
                name: Some("secp256k1_data".to_string()),
                tx_hash: "0xdddd4444".to_string(),
                output_index: 2,
                dep_type: "dep_group".to_string(),
                hash_type: Some("type".to_string()),
                data_hash: None,
                type_id: None,
            }],
        }],
    };

    manifest.write_to_root(temp.path()).unwrap();
    let read_back = DeployedManifest::read_from_root(temp.path()).unwrap().unwrap();

    assert_eq!(read_back.version, DeployedManifest::CURRENT_VERSION);
    assert_eq!(read_back.package.name, "token");
    assert_eq!(read_back.package.version, "1.0.0");
    assert_eq!(read_back.package.source_hash.as_deref(), Some("blake2b:0xabc"));
    assert_eq!(read_back.build.as_ref().unwrap().compiler_version.as_deref(), Some("0.19.0"));
    assert_eq!(read_back.build.as_ref().unwrap().artifact_hash.as_deref(), Some("blake2b:0xdef"));
    assert_eq!(read_back.deployments.len(), 1);
    assert_eq!(read_back.deployments[0].network, "aggron4");
    assert_eq!(read_back.deployments[0].code_hash, "0xbbbb2222");
    assert_eq!(read_back.deployments[0].cell_deps.len(), 1);
    assert_eq!(read_back.deployments[0].cell_deps[0].name.as_deref(), Some("secp256k1_data"));
}

#[test]
fn deployed_manifest_rejects_legacy_minimal() {
    let temp = tempfile::tempdir().unwrap();

    let toml_str = r#"
version = 1

[package]
edition = "2026"
name = "minimal"
version = "0.1.0"

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
    std::fs::write(temp.path().join("Deployed.toml"), toml_str).unwrap();

    let error = DeployedManifest::read_from_root(temp.path()).unwrap_err();
    assert!(
        error.message.contains("missing field") || error.message.contains("unsupported Deployed.toml identity"),
        "unexpected error: {}",
        error.message
    );
}

// ---------------------------------------------------------------------------
// Cell.lock — new fields round-trip
// ---------------------------------------------------------------------------

#[test]
fn lockfile_with_build_and_deployment_round_trip() {
    let temp = tempfile::tempdir().unwrap();

    let mut lockfile = Lockfile::new();
    lockfile.package = LockfilePackageInfo {
        edition: cellscript::CURRENT_EDITION,
        name: "amm_pool".to_string(),
        version: "1.0.0".to_string(),
        namespace: Some("cellscript".to_string()),
        source_hash: Some("blake2b:0xfeed".to_string()),
        compiler_source_hash: None,
        compiler_requirement: "*".to_string(),
        resolver_compiler_version: cellscript::VERSION.to_string(),
    };
    lockfile.package_build = Some(LockedBuildInfo {
        edition: cellscript::CURRENT_EDITION,
        compatibility_profile_hash: "test-compatibility-profile".to_string(),
        compiler_version: Some("0.19.0".to_string()),
        target_profile: Some("ckb-release".to_string()),
        artifact_hash: Some("blake2b:0x1234".to_string()),
        metadata_hash: Some("blake2b:0x5678".to_string()),
        schema_hash: Some("blake2b:0x9abc".to_string()),
        constraints_hash: Some("blake2b:0xdef0".to_string()),
        ..Default::default()
    });
    lockfile.deployment.insert(
        "aggron4".to_string(),
        LockfileDeploymentRef {
            record: "0xaaaa:0".to_string(),
            record_hash: Some("blake2b:0x1111".to_string()),
            code_hash: Some("0xbbbb".to_string()),
            out_point: Some("0xaaaa:0".to_string()),
            data_hash: Some("0xcccc".to_string()),
        },
    );
    lockfile.dependencies.insert(
        "token".to_string(),
        LockedDependency {
            name: "token".to_string(),
            namespace: Some("cellscript".to_string()),
            version: "0.3.0".to_string(),
            source: LockedSource::Registry {
                registry: "https://github.com/cellscript/cellscript-registry".to_string(),
                url: "https://github.com/cellscript/token".to_string(),
                revision: "abc123def456".to_string(),
                namespace: "cellscript".to_string(),
                version: "0.3.0".to_string(),
            },
            source_hash: Some("blake2b:0xaaaa".to_string()),
            manifest_digest: "sha256:test-token-manifest".to_string(),
            dependencies: BTreeMap::new(),
            build: Some(LockedBuildInfo {
                edition: cellscript::CURRENT_EDITION,
                compatibility_profile_hash: "test-compatibility-profile".to_string(),
                artifact_hash: Some("blake2b:0xtoken".to_string()),
                constraints_hash: Some("blake2b:0xtoken_constraints".to_string()),
                ..Default::default()
            }),
            compiler_requirement: "*".to_string(),
            resolver_compiler_version: cellscript::VERSION.to_string(),
        },
    );

    lockfile.write_to_root(temp.path()).unwrap();
    let read_back = Lockfile::read_from_root(temp.path()).unwrap().unwrap();

    assert_eq!(read_back.package.name, "amm_pool");
    assert_eq!(read_back.package.namespace.as_deref(), Some("cellscript"));
    assert_eq!(read_back.package.source_hash.as_deref(), Some("blake2b:0xfeed"));

    let build = read_back.package_build.unwrap();
    assert_eq!(build.artifact_hash.as_deref(), Some("blake2b:0x1234"));
    assert_eq!(build.constraints_hash.as_deref(), Some("blake2b:0xdef0"));

    let dep_ref = read_back.deployment.get("aggron4").unwrap();
    assert_eq!(dep_ref.code_hash.as_deref(), Some("0xbbbb"));
    assert_eq!(dep_ref.data_hash.as_deref(), Some("0xcccc"));

    let token_dep = read_back.dependencies.get("token").unwrap();
    assert!(matches!(token_dep.source, LockedSource::Registry { .. }));
    assert_eq!(token_dep.source_hash.as_deref(), Some("blake2b:0xaaaa"));
    assert!(token_dep.build.is_some());
}

#[test]
fn lockfile_consistency_with_registry_source() {
    use cellscript::package::PackageManifest;

    let manifest: PackageManifest = toml::from_str(
        r#"
[package]
edition = "2026"
name = "app"
version = "0.1.0"
namespace = "cellscript"

[dependencies.token]
version = "0.3.0"
namespace = "cellscript"
"#,
    )
    .unwrap();

    let mut lockfile = Lockfile::new();
    lockfile.dependencies.insert(
        "token".to_string(),
        LockedDependency {
            name: "token".to_string(),
            namespace: Some("cellscript".to_string()),
            version: "0.3.0".to_string(),
            source: LockedSource::Registry {
                registry: "https://github.com/cellscript/cellscript-registry".to_string(),
                url: "https://github.com/cellscript/token".to_string(),
                revision: "abc123".to_string(),
                namespace: "cellscript".to_string(),
                version: "0.3.0".to_string(),
            },
            source_hash: None,
            manifest_digest: "sha256:test-token-manifest".to_string(),
            dependencies: BTreeMap::new(),
            build: None,
            compiler_requirement: "*".to_string(),
            resolver_compiler_version: cellscript::VERSION.to_string(),
        },
    );
    lockfile.root.dependencies.insert("token".to_string(), "token".to_string());

    let issues = lockfile.consistency_issues(&manifest);
    assert!(issues.is_empty(), "lockfile with matching registry source should be consistent: {issues:?}");
}

// ---------------------------------------------------------------------------
// Publish flow simulation
// ---------------------------------------------------------------------------

#[test]
fn publish_flow_computes_source_hash_and_writes_registry_json() {
    let temp = tempfile::tempdir().unwrap();
    let pkg_dir = temp.path();

    create_minimal_package(pkg_dir, "my-lib", "0.1.0", Some("myns"));

    let source_hash = compute_source_hash(pkg_dir).unwrap();
    assert!(!source_hash.is_empty());

    let version = RegistryVersion {
        edition: cellscript::CURRENT_EDITION,
        compatibility_profile_hash: "test-compatibility-profile".to_string(),
        version: "0.1.0".to_string(),
        tag: "v0.1.0".to_string(),
        source_hash,
        cellscript_version: "0.19.0".to_string(),
        dependencies: BTreeMap::new(),
        abi_index: None,
        schema_hash: None,
        license: None,
        released_at: None,
        status: cellscript::package::registry::RegistryEntryStatus::VerifiedBuild,
        yanked: false,
        yanked_at: None,
        yanked_reason: None,
        replaced_by: None,
        audit: None,
        compiler_requirement: "*".to_string(),
    };

    RegistryIndex::append_version(pkg_dir, "my-lib", "myns", version).unwrap();

    let index = RegistryIndex::read_from_repo(pkg_dir).unwrap();
    assert_eq!(index.name, "my-lib");
    assert_eq!(index.namespace, "myns");
    assert_eq!(index.versions.len(), 1);
    assert_eq!(index.versions[0].version, "0.1.0");

    let recomputed = compute_source_hash(pkg_dir).unwrap();
    assert_eq!(index.versions[0].source_hash, recomputed);
}

// ---------------------------------------------------------------------------
// Full publish → verify with local Git fixture
// ---------------------------------------------------------------------------

#[test]
fn full_publish_install_verify_flow_with_local_git() {
    let temp = tempfile::tempdir().unwrap();

    // 1. Create a package source repo with a git tag
    let source_repo = temp.path().join("source-repo");
    std::fs::create_dir_all(&source_repo).unwrap();
    create_minimal_package(&source_repo, "token", "0.3.0", Some("cellscript"));

    let source_hash = compute_source_hash(&source_repo).unwrap();

    let version = RegistryVersion {
        edition: cellscript::CURRENT_EDITION,
        compatibility_profile_hash: "test-compatibility-profile".to_string(),
        version: "0.3.0".to_string(),
        tag: "v0.3.0".to_string(),
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
    RegistryIndex::append_version(&source_repo, "token", "cellscript", version).unwrap();

    git_init(&source_repo);
    git_add_all(&source_repo);
    git_commit(&source_repo, "initial version");
    git_tag(&source_repo, "v0.3.0");

    // 2. Create a discovery index repo
    let registry_repo = temp.path().join("registry-repo");
    std::fs::create_dir_all(&registry_repo).unwrap();
    git_init(&registry_repo);

    let ns_dir = registry_repo.join("cellscript");
    std::fs::create_dir_all(&ns_dir).unwrap();
    let entry = DiscoveryEntry {
        name: "token".to_string(),
        namespace: "cellscript".to_string(),
        source: source_repo.to_string_lossy().to_string(),
    };
    let entry_json = serde_json::to_string_pretty(&entry).unwrap();
    std::fs::write(ns_dir.join("token.json"), entry_json).unwrap();

    git_add_all(&registry_repo);
    git_commit(&registry_repo, "add token entry");

    // 3. Verify registry.json in the source repo is valid
    let index = RegistryIndex::read_from_repo(&source_repo).unwrap();
    assert_eq!(index.name, "token");
    assert_eq!(index.versions.len(), 1);
    assert_eq!(index.versions[0].source_hash, source_hash);

    let found = index.find_matching_version("0.3.0");
    assert!(found.is_some());
    assert_eq!(found.unwrap().version, "0.3.0");

    // 4. Verify source hash is consistent
    let recomputed = compute_source_hash(&source_repo).unwrap();
    assert_eq!(source_hash, recomputed);
}

#[test]
fn package_manager_resolves_artifact_api_dependency_with_source_hash() {
    let temp = tempfile::tempdir().unwrap();

    let source_repo = temp.path().join("source-repo");
    std::fs::create_dir_all(&source_repo).unwrap();
    create_minimal_package(&source_repo, "token", "0.3.0", Some("cellscript"));
    let source_hash = compute_source_hash(&source_repo).unwrap();
    RegistryIndex::append_version(
        &source_repo,
        "token",
        "cellscript",
        RegistryVersion {
            edition: cellscript::CURRENT_EDITION,
            compatibility_profile_hash: "test-compatibility-profile".to_string(),
            version: "0.3.0".to_string(),
            tag: "v0.3.0".to_string(),
            source_hash: source_hash.clone(),
            cellscript_version: "0.19.0".to_string(),
            dependencies: BTreeMap::new(),
            abi_index: None,
            schema_hash: None,
            license: None,
            released_at: None,
            status: cellscript::package::registry::RegistryEntryStatus::VerifiedBuild,
            yanked: false,
            yanked_at: None,
            yanked_reason: None,
            replaced_by: None,
            audit: None,
            compiler_requirement: "*".to_string(),
        },
    )
    .unwrap();
    git_init(&source_repo);
    git_add_all(&source_repo);
    git_commit(&source_repo, "publish token");
    git_tag(&source_repo, "v0.3.0");

    let registry_repo = temp.path().join("registry-repo");
    std::fs::create_dir_all(registry_repo.join("cellscript")).unwrap();
    git_init(&registry_repo);
    let entry = DiscoveryEntry {
        name: "token".to_string(),
        namespace: "cellscript".to_string(),
        source: source_repo.to_string_lossy().to_string(),
    };
    std::fs::write(registry_repo.join("cellscript/token.json"), serde_json::to_string_pretty(&entry).unwrap()).unwrap();
    git_add_all(&registry_repo);
    git_commit(&registry_repo, "add token");

    let consumer = temp.path().join("consumer");
    std::fs::create_dir_all(consumer.join("src")).unwrap();
    std::fs::write(
        consumer.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "consumer"
version = "0.1.0"
namespace = "app"

[dependencies.token]
version = "0.3.0"
namespace = "cellscript"
"#,
    )
    .unwrap();
    std::fs::write(consumer.join("src/main.cell"), "module consumer;\n").unwrap();

    let api = start_package_artifact_api(&source_repo, "verified");
    let _env = RegistryEnvGuard::new(&api.origin);
    let mut manager = PackageManager::new(&consumer);
    manager.resolve_dependencies().unwrap();
    let resolved = manager.get_resolved().values().find(|package| package.name == "token").unwrap();
    assert_eq!(resolved.source_hash.as_deref(), Some(source_hash.as_str()));

    let mut lockfile = Lockfile::new();
    lockfile.update_from_resolved(manager.get_resolved());
    let token = lockfile.dependencies.values().find(|package| package.name == "token").unwrap();
    assert_eq!(token.source_hash.as_deref(), Some(source_hash.as_str()));
    assert!(
        matches!(token.source, LockedSource::Registry { ref namespace, ref version, .. } if namespace == "cellscript" && version == "0.3.0")
    );
}

#[test]
fn package_manager_rejects_unverified_registry_entry_by_default() {
    let temp = tempfile::tempdir().unwrap();

    let source_repo = temp.path().join("source-repo");
    std::fs::create_dir_all(&source_repo).unwrap();
    create_minimal_package(&source_repo, "token", "0.3.0", Some("cellscript"));
    let source_hash = compute_source_hash(&source_repo).unwrap();
    RegistryIndex::append_version(
        &source_repo,
        "token",
        "cellscript",
        RegistryVersion {
            edition: cellscript::CURRENT_EDITION,
            compatibility_profile_hash: "test-compatibility-profile".to_string(),
            version: "0.3.0".to_string(),
            tag: "v0.3.0".to_string(),
            source_hash,
            cellscript_version: "0.20.0".to_string(),
            dependencies: BTreeMap::new(),
            abi_index: None,
            schema_hash: None,
            license: None,
            released_at: None,
            status: RegistryEntryStatus::SourcePublished,
            yanked: false,
            yanked_at: None,
            yanked_reason: None,
            replaced_by: None,
            audit: None,
            compiler_requirement: "*".to_string(),
        },
    )
    .unwrap();
    git_init(&source_repo);
    git_add_all(&source_repo);
    git_commit(&source_repo, "publish token");
    git_tag(&source_repo, "v0.3.0");

    let registry_repo = temp.path().join("registry-repo");
    std::fs::create_dir_all(registry_repo.join("cellscript")).unwrap();
    git_init(&registry_repo);
    let entry = DiscoveryEntry {
        name: "token".to_string(),
        namespace: "cellscript".to_string(),
        source: source_repo.to_string_lossy().to_string(),
    };
    std::fs::write(registry_repo.join("cellscript/token.json"), serde_json::to_string_pretty(&entry).unwrap()).unwrap();
    git_add_all(&registry_repo);
    git_commit(&registry_repo, "add token");

    let consumer = temp.path().join("consumer");
    std::fs::create_dir_all(consumer.join("src")).unwrap();
    std::fs::write(
        consumer.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "consumer"
version = "0.1.0"
namespace = "app"

[dependencies.token]
version = "0.3.0"
namespace = "cellscript"
"#,
    )
    .unwrap();
    std::fs::write(consumer.join("src/main.cell"), "module consumer;\n").unwrap();

    let api = start_package_artifact_api(&source_repo, "pending");
    let _env = RegistryEnvGuard::new(&api.origin);
    let mut manager = PackageManager::new(&consumer);
    let err = manager.resolve_dependencies().unwrap_err();
    assert!(err.message.contains("status 'source_published'"), "unexpected error: {}", err.message);
    assert!(err.message.contains("--allow-unverified"), "unexpected error: {}", err.message);
}

#[test]
fn package_manager_persists_unverified_registry_policy_in_dependency_manifest() {
    let temp = tempfile::tempdir().unwrap();

    let source_repo = temp.path().join("source-repo");
    std::fs::create_dir_all(&source_repo).unwrap();
    create_minimal_package(&source_repo, "token", "0.3.0", Some("cellscript"));
    let source_hash = compute_source_hash(&source_repo).unwrap();
    RegistryIndex::append_version(
        &source_repo,
        "token",
        "cellscript",
        RegistryVersion {
            edition: cellscript::CURRENT_EDITION,
            compatibility_profile_hash: "test-compatibility-profile".to_string(),
            version: "0.3.0".to_string(),
            tag: "v0.3.0".to_string(),
            source_hash: source_hash.clone(),
            cellscript_version: "0.20.0".to_string(),
            dependencies: BTreeMap::new(),
            abi_index: None,
            schema_hash: None,
            license: None,
            released_at: None,
            status: RegistryEntryStatus::SourcePublished,
            yanked: false,
            yanked_at: None,
            yanked_reason: None,
            replaced_by: None,
            audit: None,
            compiler_requirement: "*".to_string(),
        },
    )
    .unwrap();
    git_init(&source_repo);
    git_add_all(&source_repo);
    git_commit(&source_repo, "publish token");
    git_tag(&source_repo, "v0.3.0");

    let registry_repo = temp.path().join("registry-repo");
    std::fs::create_dir_all(registry_repo.join("cellscript")).unwrap();
    git_init(&registry_repo);
    let entry = DiscoveryEntry {
        name: "token".to_string(),
        namespace: "cellscript".to_string(),
        source: source_repo.to_string_lossy().to_string(),
    };
    std::fs::write(registry_repo.join("cellscript/token.json"), serde_json::to_string_pretty(&entry).unwrap()).unwrap();
    git_add_all(&registry_repo);
    git_commit(&registry_repo, "add token");

    let consumer = temp.path().join("consumer");
    std::fs::create_dir_all(consumer.join("src")).unwrap();
    std::fs::write(
        consumer.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "consumer"
version = "0.1.0"
namespace = "app"

[dependencies.token]
version = "0.3.0"
namespace = "cellscript"
allow_unverified = true
"#,
    )
    .unwrap();
    std::fs::write(consumer.join("src/main.cell"), "module consumer;\n").unwrap();

    let api = start_package_artifact_api(&source_repo, "pending");
    let _env = RegistryEnvGuard::new(&api.origin);
    let mut manager = PackageManager::new(&consumer);
    manager.resolve_dependencies().unwrap();
    let token = manager.get_resolved().values().find(|package| package.name == "token").unwrap();
    assert_eq!(token.source_hash.as_deref(), Some(source_hash.as_str()));
}

#[test]
fn package_manager_rejects_registry_source_hash_mismatch() {
    let temp = tempfile::tempdir().unwrap();

    let source_repo = temp.path().join("source-repo");
    std::fs::create_dir_all(&source_repo).unwrap();
    create_minimal_package(&source_repo, "token", "0.3.0", Some("cellscript"));
    RegistryIndex::append_version(
        &source_repo,
        "token",
        "cellscript",
        RegistryVersion {
            edition: cellscript::CURRENT_EDITION,
            compatibility_profile_hash: "test-compatibility-profile".to_string(),
            version: "0.3.0".to_string(),
            tag: "v0.3.0".to_string(),
            source_hash: "deliberately_wrong_hash".to_string(),
            cellscript_version: "0.19.0".to_string(),
            dependencies: BTreeMap::new(),
            abi_index: None,
            schema_hash: None,
            license: None,
            released_at: None,
            status: cellscript::package::registry::RegistryEntryStatus::VerifiedBuild,
            yanked: false,
            yanked_at: None,
            yanked_reason: None,
            replaced_by: None,
            audit: None,
            compiler_requirement: "*".to_string(),
        },
    )
    .unwrap();
    git_init(&source_repo);
    git_add_all(&source_repo);
    git_commit(&source_repo, "publish token");
    git_tag(&source_repo, "v0.3.0");

    let registry_repo = temp.path().join("registry-repo");
    std::fs::create_dir_all(registry_repo.join("cellscript")).unwrap();
    git_init(&registry_repo);
    let entry = DiscoveryEntry {
        name: "token".to_string(),
        namespace: "cellscript".to_string(),
        source: source_repo.to_string_lossy().to_string(),
    };
    std::fs::write(registry_repo.join("cellscript/token.json"), serde_json::to_string_pretty(&entry).unwrap()).unwrap();
    git_add_all(&registry_repo);
    git_commit(&registry_repo, "add token");

    let consumer = temp.path().join("consumer");
    std::fs::create_dir_all(consumer.join("src")).unwrap();
    std::fs::write(
        consumer.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "consumer"
version = "0.1.0"
namespace = "app"

[dependencies.token]
version = "0.3.0"
namespace = "cellscript"
"#,
    )
    .unwrap();
    std::fs::write(consumer.join("src/main.cell"), "module consumer;\n").unwrap();

    let api = start_package_artifact_api(&source_repo, "verified");
    let _env = RegistryEnvGuard::new(&api.origin);
    let mut manager = PackageManager::new(&consumer);
    let err = manager.resolve_dependencies().unwrap_err();
    assert!(
        err.message.contains("source_hash") && err.message.contains("deliberately_wrong_hash"),
        "unexpected error: {}",
        err.message
    );
}

// ---------------------------------------------------------------------------
// Fail-closed verification
// ---------------------------------------------------------------------------
// Note: artifact_hash / code_hash mismatch detection is covered by CLI
// integration paths that exercise package identity instead of re-implementing
// the comparison inline:
// `cellc_gen_builder_lockfile_identity_fails_closed` and
// `cellc_build_omits_lockfile_deployment_when_artifact_hash_mismatches`.

#[test]
fn package_verify_detects_missing_source_hash() {
    let temp = tempfile::tempdir().unwrap();
    create_minimal_package(temp.path(), "verify-test", "0.1.0", None);

    let mut lockfile = Lockfile::new();
    lockfile.package = LockfilePackageInfo {
        edition: cellscript::CURRENT_EDITION,
        name: "verify-test".to_string(),
        version: "0.1.0".to_string(),
        namespace: None,
        source_hash: Some("deliberately_wrong_hash".to_string()),
        compiler_source_hash: None,
        compiler_requirement: "*".to_string(),
        resolver_compiler_version: cellscript::VERSION.to_string(),
    };
    lockfile.write_to_root(temp.path()).unwrap();

    let lockfile = Lockfile::read_from_root(temp.path()).unwrap().unwrap();
    let computed = compute_source_hash(temp.path()).unwrap();
    let stored = lockfile.package.source_hash.unwrap();

    assert_ne!(computed, stored);
}

#[test]
fn lockfile_consistency_rejects_wrong_registry_namespace() {
    use cellscript::package::PackageManifest;

    let manifest: PackageManifest = toml::from_str(
        r#"
[package]
edition = "2026"
name = "app"
version = "0.1.0"
namespace = "cellscript"

[dependencies.token]
version = "0.3.0"
namespace = "cellscript"
"#,
    )
    .unwrap();

    let mut lockfile = Lockfile::new();
    lockfile.dependencies.insert(
        "token".to_string(),
        LockedDependency {
            name: "token".to_string(),
            namespace: Some("other".to_string()),
            version: "0.3.0".to_string(),
            source: LockedSource::Registry {
                registry: "https://github.com/cellscript/cellscript-registry".to_string(),
                url: "https://github.com/cellscript/token".to_string(),
                revision: "abc123".to_string(),
                namespace: "other".to_string(),
                version: "0.3.0".to_string(),
            },
            source_hash: None,
            manifest_digest: "sha256:test-token-manifest".to_string(),
            dependencies: BTreeMap::new(),
            build: None,
            compiler_requirement: "*".to_string(),
            resolver_compiler_version: cellscript::VERSION.to_string(),
        },
    );
    lockfile.root.dependencies.insert("token".to_string(), "token".to_string());

    let issues = lockfile.consistency_issues(&manifest);
    assert!(!issues.is_empty(), "wrong namespace should cause consistency issues: {issues:?}");
    assert!(
        issues.iter().any(|i| i.contains("token") || i.contains("registry")),
        "at least one issue should mention the dependency or registry: {issues:?}"
    );
}

#[test]
fn lockfile_consistency_accepts_matching_registry_source() {
    use cellscript::package::PackageManifest;

    let manifest: PackageManifest = toml::from_str(
        r#"
[package]
edition = "2026"
name = "app"
version = "0.1.0"
namespace = "cellscript"

[dependencies.token]
version = "0.3.0"
namespace = "cellscript"
"#,
    )
    .unwrap();

    let mut lockfile = Lockfile::new();
    lockfile.dependencies.insert(
        "token".to_string(),
        LockedDependency {
            name: "token".to_string(),
            namespace: Some("cellscript".to_string()),
            version: "0.3.0".to_string(),
            source: LockedSource::Registry {
                registry: "https://github.com/cellscript/cellscript-registry".to_string(),
                url: "https://github.com/cellscript/token".to_string(),
                revision: "abc123".to_string(),
                namespace: "cellscript".to_string(),
                version: "0.3.0".to_string(),
            },
            source_hash: None,
            manifest_digest: "sha256:test-token-manifest".to_string(),
            dependencies: BTreeMap::new(),
            build: None,
            compiler_requirement: "*".to_string(),
            resolver_compiler_version: cellscript::VERSION.to_string(),
        },
    );
    lockfile.root.dependencies.insert("token".to_string(), "token".to_string());

    let issues = lockfile.consistency_issues(&manifest);
    assert!(issues.is_empty(), "matching registry source should have no issues: {issues:?}");
}

// ---------------------------------------------------------------------------
// Multi-deployment records
// ---------------------------------------------------------------------------

#[test]
fn deployed_manifest_supports_multiple_deployments() {
    let temp = tempfile::tempdir().unwrap();

    let manifest = DeployedManifest {
        version: DeployedManifest::CURRENT_VERSION,
        schema: DEPLOYED_MANIFEST_SCHEMA.to_string(),
        package: DeployedPackageInfo {
            edition: cellscript::CURRENT_EDITION,
            name: "token".to_string(),
            version: "1.0.0".to_string(),
            source_hash: None,
        },
        build: None,
        deployments: vec![
            DeploymentRecord {
                edition: cellscript::CURRENT_EDITION,
                compatibility_profile_hash: "test-compatibility-profile".to_string(),
                network: "ckb-mainnet".to_string(),
                chain_id: "ckb-mainnet".to_string(),
                tx_hash: "0x1111".to_string(),
                output_index: 0,
                code_hash: "0x2222".to_string(),
                hash_type: "type".to_string(),
                dep_type: "code".to_string(),
                data_hash: "0x3333".to_string(),
                out_point: "0x1111:0".to_string(),
                artifact_hash: None,
                metadata_hash: None,
                schema_hash: None,
                cell_data_codec_manifest_hash: None,
                abi_hash: None,
                constraints_hash: None,
                compiler_version: None,
                type_id: None,
                script_role: None,
                status: Some(DeploymentStatus::Active),
                upgrade_lineage: None,
                audit_report_hash: None,
                publisher_signature: None,
                cell_deps: vec![],
            },
            DeploymentRecord {
                edition: cellscript::CURRENT_EDITION,
                compatibility_profile_hash: "test-compatibility-profile".to_string(),
                network: "aggron4".to_string(),
                chain_id: "ckb-testnet".to_string(),
                tx_hash: "0x4444".to_string(),
                output_index: 1,
                code_hash: "0x5555".to_string(),
                hash_type: "data1".to_string(),
                dep_type: "code".to_string(),
                data_hash: "0x6666".to_string(),
                out_point: "0x4444:1".to_string(),
                artifact_hash: None,
                metadata_hash: None,
                schema_hash: None,
                cell_data_codec_manifest_hash: None,
                abi_hash: None,
                constraints_hash: None,
                compiler_version: None,
                type_id: None,
                script_role: None,
                status: Some(DeploymentStatus::Candidate),
                upgrade_lineage: None,
                audit_report_hash: None,
                publisher_signature: None,
                cell_deps: vec![],
            },
        ],
    };

    manifest.write_to_root(temp.path()).unwrap();
    let read_back = DeployedManifest::read_from_root(temp.path()).unwrap().unwrap();

    assert_eq!(read_back.deployments.len(), 2);
    assert_eq!(read_back.deployments[0].network, "ckb-mainnet");
    assert_eq!(read_back.deployments[0].status, Some(DeploymentStatus::Active));
    assert_eq!(read_back.deployments[1].network, "aggron4");
    assert_eq!(read_back.deployments[1].status, Some(DeploymentStatus::Candidate));
}
