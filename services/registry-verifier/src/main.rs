//! Isolated source/build verifier used by the production Registry worker.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use base64::Engine as _;
use camino::Utf8PathBuf;
use serde::{Deserialize, Serialize};

const MAX_SNAPSHOT_BYTES: u64 = 5 * 1024 * 1024;
const PROTOCOL_BUNDLE_SCHEMA: &str = "cellscript-protocol-bundle-v1";
const PROTOCOL_BUNDLE_ARTIFACT_BINDING_SCHEMA: &str = "cellscript-protocol-bundle-artifact-binding-v1";
const PROTOCOL_BUNDLE_RUNTIME_ADAPTER: &str = "cellscript-ckb-adapter";

#[derive(Debug)]
struct Args {
    snapshot: PathBuf,
    namespace: String,
    name: String,
    version: String,
    source_hash: String,
    manifest_hash: String,
    artifact_kind: String,
    profile: String,
    compatibility_profile_hash: Option<String>,
    interface_hash: Option<String>,
    artifact_hash: Option<String>,
    abi_hash: Option<String>,
    build_recipe_hash: Option<String>,
}

#[derive(Debug, Serialize)]
struct VerificationOutput {
    status: &'static str,
    verification_level: &'static str,
    artifact_hash: Option<String>,
    metadata_hash: String,
    compiler_version: Option<String>,
    source_hash: String,
    manifest_hash: String,
    compatibility_profile_hash: Option<String>,
    interface_hash: Option<String>,
    artifact_format: String,
    checker_version: Option<String>,
    checker_policy_schema: Option<String>,
    checker_report_hash: Option<String>,
    protocol_bundle_schema: Option<&'static str>,
    protocol_bundle_artifact_binding_schema: Option<&'static str>,
    protocol_bundle_runtime_adapter: Option<&'static str>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactBundle {
    schema: String,
    namespace: String,
    name: String,
    release: String,
    profile: String,
    manifest_json: String,
    objects: Vec<ArtifactBundleObject>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactBundleObject {
    role: String,
    content_base64: String,
}

#[derive(Serialize)]
struct FailureOutput<'a> {
    status: &'static str,
    error_code: &'static str,
    message: &'a str,
}

fn main() -> ExitCode {
    match run() {
        Ok(output) => {
            if let Err(error) = serde_json::to_writer(std::io::stdout(), &output) {
                eprintln!("failed to serialize verifier output: {error}");
                return ExitCode::from(70);
            }
            println!();
            ExitCode::SUCCESS
        }
        Err(error) => {
            let message = error.to_string();
            let output = FailureOutput { status: "failed", error_code: verifier_error_code(&error), message: &message };
            let _ = serde_json::to_writer(std::io::stdout(), &output);
            println!();
            ExitCode::from(1)
        }
    }
}

fn verifier_error_code(error: &anyhow::Error) -> &'static str {
    let messages = error.chain().map(ToString::to_string).collect::<Vec<_>>();
    let contains = |needle: &str| messages.iter().any(|message| message.contains(needle));
    let starts_with = |prefix: &str| messages.iter().any(|message| message.starts_with(prefix));

    if starts_with("unexpected positional argument")
        || starts_with("missing value for")
        || starts_with("duplicate argument")
        || starts_with("missing required argument")
        || starts_with("unknown argument")
        || contains("requires --")
    {
        "invalid_arguments"
    } else if contains("failed to inspect source snapshot") || contains("failed to read source snapshot") {
        "snapshot_unavailable"
    } else if contains("source snapshot must be a non-empty regular file") {
        "snapshot_invalid"
    } else if contains("source snapshot authentication failed") {
        "snapshot_authentication_failed"
    } else if contains("unsupported artifact profile") || contains("unsupported artifact bundle profile") {
        "unsupported_profile"
    } else if contains("package identity does not match") || contains("artifact bundle identity does not match") {
        "artifact_identity_mismatch"
    } else if contains("_hash mismatch") {
        "identity_hash_mismatch"
    } else if contains("CellScript package compilation failed") {
        "cellscript_compilation_failed"
    } else if contains("independent checker rejected") || messages.iter().any(|message| message.starts_with('V')) {
        "artifact_checker_rejected"
    } else if contains("artifact bundle") {
        "artifact_bundle_invalid"
    } else if contains("artifact profile contract") {
        "profile_contract_invalid"
    } else if contains("failed to read materialized Cell.toml") || contains("canonical package manifest") {
        "manifest_invalid"
    } else {
        "verifier_internal_error"
    }
}

fn run() -> Result<VerificationOutput> {
    let args = parse_args()?;
    verify(args)
}

fn verify(args: Args) -> Result<VerificationOutput> {
    let metadata =
        fs::metadata(&args.snapshot).with_context(|| format!("failed to inspect source snapshot '{}'", args.snapshot.display()))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_SNAPSHOT_BYTES {
        bail!("source snapshot must be a non-empty regular file no larger than {MAX_SNAPSHOT_BYTES} bytes");
    }
    let snapshot =
        fs::read(&args.snapshot).with_context(|| format!("failed to read source snapshot '{}'", args.snapshot.display()))?;

    match args.profile.as_str() {
        "cellscript_source" => verify_cellscript_source(args, &snapshot),
        "ckb_executable" | "reproducible_build" | "copy_material" => verify_artifact_bundle(args, &snapshot),
        profile => bail!("unsupported artifact profile '{profile}'"),
    }
}

fn verify_cellscript_source(args: Args, snapshot: &[u8]) -> Result<VerificationOutput> {
    let compatibility_profile_expected =
        args.compatibility_profile_hash.as_deref().context("cellscript_source requires --compatibility-profile-hash")?;
    let interface_expected = args.interface_hash.as_deref().context("cellscript_source requires --interface-hash")?;

    let work = unique_work_dir()?;
    let _cleanup = Cleanup(work.clone());
    cellscript::package::registry::materialize_generated_source_snapshot_bytes(
        snapshot,
        &work,
        &args.namespace,
        &args.name,
        &args.version,
        &args.source_hash,
    )
    .context("source snapshot authentication failed")?;

    let package_manager = cellscript::package::PackageManager::new(&work);
    let manifest = package_manager.read_manifest().context("failed to read materialized Cell.toml")?;
    if manifest.package.namespace.as_deref() != Some(args.namespace.as_str())
        || manifest.package.name != args.name
        || manifest.package.version != args.version
    {
        bail!("materialized package identity does not match the verification job");
    }
    let manifest_hash = cellscript::package::registry::compute_package_manifest_hash(&manifest)
        .context("failed to compute canonical package manifest hash")?;
    require_matching_hash("manifest_hash", &manifest_hash, &args.manifest_hash)?;

    let compile_root = Utf8PathBuf::from_path_buf(work.clone())
        .map_err(|path| anyhow::anyhow!("verification work path is not valid UTF-8: {}", path.display()))?;
    let result = cellscript::compile_path(&compile_root, cellscript::CompileOptions::default())
        .context("CellScript package compilation failed")?;
    let compatibility_profile_bytes =
        serde_json::to_vec(&result.metadata.compatibility_profile).context("failed to serialize compatibility profile")?;
    let compatibility_profile_hash = hex::encode(cellscript::ckb_blake2b256(&compatibility_profile_bytes));
    require_matching_hash("compatibility_profile_hash", &compatibility_profile_hash, compatibility_profile_expected)?;
    require_matching_hash("interface_hash", &result.metadata.interface_hash, interface_expected)?;

    let artifact_hash = result.metadata.artifact_hash.clone().unwrap_or_else(|| hex::encode(result.artifact_hash));
    let metadata_bytes = serde_json::to_vec(&result.metadata).context("failed to serialize compile metadata")?;
    let metadata_hash = hex::encode(cellscript::ckb_blake2b256(&metadata_bytes));

    Ok(VerificationOutput {
        status: "passed",
        verification_level: "compiled",
        artifact_hash: Some(artifact_hash),
        metadata_hash,
        compiler_version: Some(result.metadata.compiler_version),
        source_hash: args.source_hash,
        manifest_hash: args.manifest_hash,
        compatibility_profile_hash: args.compatibility_profile_hash,
        interface_hash: args.interface_hash,
        artifact_format: result.artifact_format.display_name().to_string(),
        checker_version: None,
        checker_policy_schema: None,
        checker_report_hash: None,
        protocol_bundle_schema: None,
        protocol_bundle_artifact_binding_schema: None,
        protocol_bundle_runtime_adapter: None,
    })
}

fn verify_artifact_bundle(args: Args, snapshot: &[u8]) -> Result<VerificationOutput> {
    let bundle: ArtifactBundle = serde_json::from_slice(snapshot).context("artifact bundle must be valid JSON")?;
    if bundle.schema != "cellscript-registry-bundle" {
        bail!("artifact bundle schema must be 'cellscript-registry-bundle'");
    }
    if bundle.namespace != args.namespace
        || bundle.name != args.name
        || bundle.release != args.version
        || bundle.profile != args.profile
    {
        bail!("artifact bundle identity does not match the verification job");
    }
    let manifest: serde_json::Value =
        serde_json::from_str(&bundle.manifest_json).context("artifact bundle manifest_json must be valid JSON")?;
    if !manifest.is_object() {
        bail!("artifact bundle manifest_json must encode a JSON object");
    }
    validate_bundle_roles(&bundle, &args.profile, &manifest)?;
    let canonical_manifest = cellscript::package::registry::canonical_artifact_contract_json(&manifest)
        .map_err(anyhow::Error::msg)
        .context("artifact profile contract canonicalization failed")?;
    let manifest_hash = hex::encode(cellscript::ckb_blake2b256(canonical_manifest.as_bytes()));
    require_matching_hash("manifest_hash", &manifest_hash, &args.manifest_hash)?;
    let source = bundle_object(&bundle, "source")?;
    let source_hash = hex::encode(cellscript::ckb_blake2b256(&source));
    require_matching_hash("source_hash", &source_hash, &args.source_hash)?;
    let audit_report_hash = if manifest.pointer("/security/audit_report_hash").is_some() {
        Some(hex::encode(cellscript::ckb_blake2b256(&bundle_object(&bundle, "audit_report")?)))
    } else {
        None
    };

    let mut checker_version = None;
    let mut checker_policy_schema = None;
    let mut checker_report_hash = None;
    let mut verified_compatibility_profile_hash = None;
    let (artifact_hash, abi_hash, build_recipe_hash, artifact_format, verification_level) = match args.profile.as_str() {
        "ckb_executable" => {
            let executable = bundle_object(&bundle, "executable")?;
            let actual_artifact_hash = hex::encode(cellscript::ckb_blake2b256(&executable));
            require_matching_hash(
                "artifact_hash",
                &actual_artifact_hash,
                args.artifact_hash.as_deref().context("ckb_executable requires --artifact-hash")?,
            )?;
            let abi = bundle_object(&bundle, "abi")?;
            let actual_abi_hash = hex::encode(cellscript::ckb_blake2b256(&abi));
            require_matching_hash(
                "abi_hash",
                &actual_abi_hash,
                args.abi_hash.as_deref().context("ckb_executable requires --abi-hash")?,
            )?;
            let actual_recipe_hash = if manifest.pointer("/build/reproducible").and_then(serde_json::Value::as_bool) == Some(true) {
                let recipe = bundle_object(&bundle, "build_recipe")?;
                let hash = hex::encode(cellscript::ckb_blake2b256(&recipe));
                require_matching_hash(
                    "build_recipe_hash",
                    &hash,
                    args.build_recipe_hash.as_deref().context("reproducible ckb_executable requires --build-recipe-hash")?,
                )?;
                Some(hash)
            } else {
                None
            };
            let metadata = bundle_object(&bundle, "metadata")?;
            let lowering_record = bundle_object(&bundle, "lowering_record")?;
            let source_map = bundle_object(&bundle, "source_map")?;
            let budgets = cellscript_artifact_checker::CheckerBudgets::default();
            let checker_report =
                cellscript_artifact_checker::check_bundle(&executable, &metadata, &lowering_record, &source_map, &budgets)
                    .map_err(anyhow::Error::msg)
                    .context("artifact bundle independent checker rejected the CKB executable")?;
            let report_bytes = cellscript_artifact_checker::canonical_bytes(&checker_report)
                .map_err(anyhow::Error::msg)
                .context("failed to canonicalize artifact checker report")?;
            let record = cellscript_artifact_checker::parse_lowering_record(&lowering_record, &budgets)
                .map_err(anyhow::Error::msg)
                .context("failed to read checker-approved lowering record")?;
            checker_version = Some(checker_report.checker_version);
            checker_policy_schema = Some(checker_report.checker_policy_schema);
            checker_report_hash = Some(hex::encode(cellscript_artifact_checker::ckb_blake2b256(&report_bytes)));
            verified_compatibility_profile_hash = Some(record.compatibility_profile_hash);
            (Some(actual_artifact_hash), Some(actual_abi_hash), actual_recipe_hash, "ckb-vm-executable", "structurally_verified")
        }
        "reproducible_build" => {
            let executable = bundle_object(&bundle, "executable")?;
            let actual_artifact_hash = hex::encode(cellscript::ckb_blake2b256(&executable));
            require_matching_hash(
                "artifact_hash",
                &actual_artifact_hash,
                args.artifact_hash.as_deref().context("reproducible_build requires --artifact-hash")?,
            )?;
            let recipe = bundle_object(&bundle, "build_recipe")?;
            let actual_recipe_hash = hex::encode(cellscript::ckb_blake2b256(&recipe));
            require_matching_hash(
                "build_recipe_hash",
                &actual_recipe_hash,
                args.build_recipe_hash.as_deref().context("reproducible_build requires --build-recipe-hash")?,
            )?;
            (Some(actual_artifact_hash), None, Some(actual_recipe_hash), "reproducible-binary", "evidence_required")
        }
        "copy_material" => (None, None, None, "copy-material", "hash_bound"),
        _ => unreachable!("profile was checked before bundle verification"),
    };
    let (abi_sha256, executable_ls_idl_bound) = if manifest.get("interface").is_some() {
        use sha2::Digest as _;
        let abi = bundle_object(&bundle, "abi")?;
        cellscript::package::registry::validate_ls_idl_document(&abi)
            .map_err(anyhow::Error::msg)
            .context("LS-IDL schema validation failed")?;
        let digest = sha2::Sha256::digest(&abi);
        let executable = bundle_object(&bundle, "executable")?;
        let digest: [u8; 32] = digest.into();
        (Some(hex::encode(digest)), Some(executable.ends_with(&digest)))
    } else {
        (None, None)
    };
    cellscript::package::registry::validate_artifact_profile_contract(
        &args.artifact_kind,
        &args.profile,
        &manifest,
        cellscript::package::registry::ArtifactContractHashes {
            artifact_hash: artifact_hash.as_deref(),
            abi_hash: abi_hash.as_deref(),
            abi_sha256: abi_sha256.as_deref(),
            executable_ls_idl_bound,
            build_recipe_hash: build_recipe_hash.as_deref(),
            audit_report_hash: audit_report_hash.as_deref(),
        },
    )
    .map_err(anyhow::Error::msg)
    .context("artifact profile contract validation failed")?;
    let metadata_hash = hex::encode(cellscript::ckb_blake2b256(snapshot));
    let supports_protocol_bundle = verification_level == "structurally_verified" && artifact_format == "ckb-vm-executable";
    Ok(VerificationOutput {
        status: "passed",
        verification_level,
        artifact_hash,
        metadata_hash,
        compiler_version: None,
        source_hash: args.source_hash,
        manifest_hash: args.manifest_hash,
        compatibility_profile_hash: verified_compatibility_profile_hash,
        interface_hash: None,
        artifact_format: artifact_format.to_string(),
        checker_version,
        checker_policy_schema,
        checker_report_hash,
        protocol_bundle_schema: supports_protocol_bundle.then_some(PROTOCOL_BUNDLE_SCHEMA),
        protocol_bundle_artifact_binding_schema: supports_protocol_bundle.then_some(PROTOCOL_BUNDLE_ARTIFACT_BINDING_SCHEMA),
        protocol_bundle_runtime_adapter: supports_protocol_bundle.then_some(PROTOCOL_BUNDLE_RUNTIME_ADAPTER),
    })
}

fn bundle_object(bundle: &ArtifactBundle, role: &str) -> Result<Vec<u8>> {
    let mut matching = bundle.objects.iter().filter(|object| object.role == role);
    let object = matching.next().with_context(|| format!("artifact bundle is missing required '{role}' object"))?;
    if matching.next().is_some() {
        bail!("artifact bundle contains more than one '{role}' object");
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(&object.content_base64)
        .with_context(|| format!("artifact bundle '{role}' object is not valid base64"))?;
    if bytes.is_empty() {
        bail!("artifact bundle '{role}' object must not be empty");
    }
    Ok(bytes)
}

fn validate_bundle_roles(bundle: &ArtifactBundle, profile: &str, contract: &serde_json::Value) -> Result<()> {
    let mut required = match profile {
        "ckb_executable" => vec!["source", "executable", "abi", "metadata", "lowering_record", "source_map"],
        "reproducible_build" => vec!["source", "executable", "build_recipe"],
        "copy_material" => vec!["source"],
        other => bail!("unsupported artifact bundle profile '{other}'"),
    };
    if contract.pointer("/security/audit_report_hash").is_some() {
        required.push("audit_report");
    }
    if profile == "ckb_executable" && contract.pointer("/build/reproducible").and_then(serde_json::Value::as_bool) == Some(true) {
        required.push("build_recipe");
    }
    let mut seen = std::collections::BTreeSet::new();
    for object in &bundle.objects {
        if !required.contains(&object.role.as_str()) {
            bail!("artifact bundle role '{}' is not allowed for profile '{profile}'", object.role);
        }
        if !seen.insert(object.role.as_str()) {
            bail!("artifact bundle contains more than one '{}' object", object.role);
        }
    }
    for role in required {
        if !seen.contains(role) {
            bail!("artifact bundle is missing required '{role}' object");
        }
    }
    Ok(())
}

fn parse_args() -> Result<Args> {
    let mut values = BTreeMap::new();
    let mut arguments = env::args().skip(1);
    while let Some(flag) = arguments.next() {
        if !flag.starts_with("--") {
            bail!("unexpected positional argument '{flag}'");
        }
        let value = arguments.next().with_context(|| format!("missing value for '{flag}'"))?;
        if values.insert(flag.clone(), value).is_some() {
            bail!("duplicate argument '{flag}'");
        }
    }
    let mut take = |name: &str| values.remove(name).with_context(|| format!("missing required argument '{name}'"));
    let args = Args {
        snapshot: PathBuf::from(take("--snapshot")?),
        namespace: take("--namespace")?,
        name: take("--name")?,
        version: take("--version")?,
        source_hash: take("--source-hash")?,
        manifest_hash: take("--manifest-hash")?,
        artifact_kind: take("--artifact-kind")?,
        profile: take("--profile")?,
        compatibility_profile_hash: values.remove("--compatibility-profile-hash"),
        interface_hash: values.remove("--interface-hash"),
        artifact_hash: values.remove("--artifact-hash"),
        abi_hash: values.remove("--abi-hash"),
        build_recipe_hash: values.remove("--build-recipe-hash"),
    };
    if let Some((unknown, _)) = values.into_iter().next() {
        bail!("unknown argument '{unknown}'");
    }
    Ok(args)
}

fn require_matching_hash(field: &str, actual: &str, expected: &str) -> Result<()> {
    let normalize = |value: &str| value.strip_prefix("0x").unwrap_or(value).to_ascii_lowercase();
    let actual = normalize(actual);
    let expected = normalize(expected);
    if actual.len() != 64 || expected.len() != 64 || actual != expected {
        bail!("{field} mismatch: compiled/materialized value does not match the signed Registry identity");
    }
    Ok(())
}

fn unique_work_dir() -> Result<PathBuf> {
    let root = env::temp_dir();
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).context("system clock is before the Unix epoch")?.as_nanos();
    for attempt in 0..100_u32 {
        let candidate = root.join(format!("cellscript-registry-verify-{}-{timestamp}-{attempt}", std::process::id()));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    bail!("failed to allocate a unique verifier work directory")
}

struct Cleanup(PathBuf);

impl Drop for Cleanup {
    fn drop(&mut self) {
        if self.0.starts_with(env::temp_dir())
            && self.0.file_name().is_some_and(|name| name.to_string_lossy().starts_with("cellscript-registry-verify-"))
        {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use serde_json::json;

    use super::*;

    struct VerifiedCkbFixture {
        source: Vec<u8>,
        executable: Vec<u8>,
        abi: Vec<u8>,
        metadata: Vec<u8>,
        lowering_record: Vec<u8>,
        source_map: Vec<u8>,
    }

    impl VerifiedCkbFixture {
        fn new() -> Self {
            let source = br#"module registry_fixture

action main() {
    verification
}
"#
            .to_vec();
            let result = cellscript::compile(
                std::str::from_utf8(&source).unwrap(),
                cellscript::CompileOptions { target: Some("riscv64-elf".to_string()), ..Default::default() },
            )
            .unwrap();
            Self {
                source,
                executable: result.artifact_bytes,
                abi: br#"{"actions":["main"]}"#.to_vec(),
                metadata: serde_json::to_vec(&result.metadata).unwrap(),
                lowering_record: cellscript_artifact_checker::canonical_bytes(result.verified_lowering_record.as_ref().unwrap())
                    .unwrap(),
                source_map: cellscript_artifact_checker::canonical_bytes(result.source_artifact_map.as_ref().unwrap()).unwrap(),
            }
        }

        fn objects(&self) -> Vec<(&str, &[u8])> {
            vec![
                ("source", &self.source),
                ("executable", &self.executable),
                ("abi", &self.abi),
                ("metadata", &self.metadata),
                ("lowering_record", &self.lowering_record),
                ("source_map", &self.source_map),
            ]
        }
    }

    #[test]
    fn exposes_stable_machine_codes_for_verification_boundaries() {
        let cases = [
            (anyhow::anyhow!("missing required argument '--snapshot'"), "invalid_arguments"),
            (anyhow::anyhow!("artifact_hash mismatch: signed identity differs"), "identity_hash_mismatch"),
            (anyhow::anyhow!("artifact bundle must be valid JSON"), "artifact_bundle_invalid"),
            (anyhow::anyhow!("CellScript package compilation failed"), "cellscript_compilation_failed"),
            (anyhow::anyhow!("unsupported artifact profile 'unknown'"), "unsupported_profile"),
        ];
        for (error, expected) in cases {
            assert_eq!(verifier_error_code(&error), expected, "unexpected code for {error:#}");
        }

        let authenticated = anyhow::anyhow!("invalid file hash").context("source snapshot authentication failed");
        assert_eq!(verifier_error_code(&authenticated), "snapshot_authentication_failed");
    }

    #[test]
    fn verifies_generated_snapshot_with_the_real_compiler() {
        let source_root = tempfile::tempdir().unwrap();
        fs::create_dir_all(source_root.path().join("src")).unwrap();
        fs::write(
            source_root.path().join("Cell.toml"),
            r#"[package]
edition = "2026"
name = "demo"
version = "1.2.3"
namespace = "cellscript"
entry = "src/main.cell"
"#,
        )
        .unwrap();
        fs::write(
            source_root.path().join("src/main.cell"),
            r#"module demo::main

action identity(value: u64) -> u64 {
    verification
        value
}
"#,
        )
        .unwrap();

        let source_hash = cellscript::package::registry::compute_source_hash(source_root.path()).unwrap();
        let manager = cellscript::package::PackageManager::new(source_root.path());
        let manifest = manager.read_manifest().unwrap();
        let manifest_hash = cellscript::package::registry::compute_package_manifest_hash(&manifest).unwrap();
        let compile_root = Utf8PathBuf::from_path_buf(source_root.path().to_path_buf()).unwrap();
        let result = cellscript::compile_path(&compile_root, cellscript::CompileOptions::default()).unwrap();
        let compatibility_profile_hash =
            hex::encode(cellscript::ckb_blake2b256(&serde_json::to_vec(&result.metadata.compatibility_profile).unwrap()));

        let mut files = Vec::new();
        for relative in ["Cell.toml", "src/main.cell"] {
            let content = fs::read(source_root.path().join(relative)).unwrap();
            files.push(json!({
                "path": relative,
                "blake2b256": hex::encode(cellscript::ckb_blake2b256(&content)),
                "content_base64": base64::engine::general_purpose::STANDARD.encode(content),
            }));
        }
        let snapshot = json!({
            "schema": "cellscript-source-snapshot-v1",
            "generated_by": cellscript::VERSION,
            "package": { "namespace": "cellscript", "name": "demo", "version": "1.2.3" },
            "files": files,
        });
        let snapshot_path = source_root.path().join("snapshot.json");
        fs::write(&snapshot_path, serde_json::to_vec(&snapshot).unwrap()).unwrap();

        let output = verify(Args {
            snapshot: snapshot_path,
            namespace: "cellscript".to_string(),
            name: "demo".to_string(),
            version: "1.2.3".to_string(),
            source_hash: source_hash.clone(),
            manifest_hash: manifest_hash.clone(),
            artifact_kind: "source_library".to_string(),
            profile: "cellscript_source".to_string(),
            compatibility_profile_hash: Some(compatibility_profile_hash.clone()),
            interface_hash: Some(result.metadata.interface_hash.clone()),
            artifact_hash: None,
            abi_hash: None,
            build_recipe_hash: None,
        })
        .unwrap();
        assert_eq!(output.status, "passed");
        assert_eq!(output.source_hash, source_hash);
        assert_eq!(output.manifest_hash, manifest_hash);
        assert_eq!(output.compatibility_profile_hash.as_deref(), Some(compatibility_profile_hash.as_str()));
        assert_eq!(output.interface_hash.as_deref(), Some(result.metadata.interface_hash.as_str()));
        assert_eq!(output.artifact_hash.as_deref().unwrap().len(), 64);
        assert_eq!(output.metadata_hash.len(), 64);
        assert!(output.protocol_bundle_schema.is_none());
        assert!(output.protocol_bundle_artifact_binding_schema.is_none());
        assert!(output.protocol_bundle_runtime_adapter.is_none());
    }

    #[test]
    fn hash_binds_ckb_executable_and_abi_bundle_objects() {
        let fixture = VerifiedCkbFixture::new();
        let output = verify_bundle(
            "ckb_executable",
            &fixture.objects(),
            Some(hex::encode(cellscript::ckb_blake2b256(&fixture.executable))),
            Some(hex::encode(cellscript::ckb_blake2b256(&fixture.abi))),
            None,
        )
        .unwrap();
        assert_eq!(output.status, "passed");
        assert_eq!(output.verification_level, "structurally_verified");
        assert_eq!(output.artifact_format, "ckb-vm-executable");
        assert_eq!(output.checker_version.as_deref(), Some(cellscript_artifact_checker::CHECKER_VERSION));
        assert_eq!(output.checker_policy_schema.as_deref(), Some(cellscript_artifact_checker::CHECKER_POLICY_SCHEMA));
        assert_eq!(output.checker_report_hash.as_deref().unwrap().len(), 64);
        assert_eq!(output.protocol_bundle_schema, Some(PROTOCOL_BUNDLE_SCHEMA));
        assert_eq!(output.protocol_bundle_artifact_binding_schema, Some(PROTOCOL_BUNDLE_ARTIFACT_BINDING_SCHEMA));
        assert_eq!(output.protocol_bundle_runtime_adapter, Some(PROTOCOL_BUNDLE_RUNTIME_ADAPTER));
    }

    #[test]
    fn deployed_ckb_executable_can_bind_a_reproducible_recipe() {
        let fixture = VerifiedCkbFixture::new();
        let recipe = b"pinned build recipe";
        let mut objects = fixture.objects();
        objects.push(("build_recipe", recipe));
        let output = verify_bundle(
            "ckb_executable",
            &objects,
            Some(hex::encode(cellscript::ckb_blake2b256(&fixture.executable))),
            Some(hex::encode(cellscript::ckb_blake2b256(&fixture.abi))),
            Some(hex::encode(cellscript::ckb_blake2b256(recipe))),
        )
        .unwrap();
        assert_eq!(output.verification_level, "structurally_verified");
    }

    #[test]
    fn distinguishes_reproducible_build_evidence_from_copy_material() {
        let executable = b"reproducible-output";
        let recipe = b"FROM rust:latest";
        let reproducible = verify_bundle(
            "reproducible_build",
            &[("source", b"source"), ("executable", executable), ("build_recipe", recipe)],
            Some(hex::encode(cellscript::ckb_blake2b256(executable))),
            None,
            Some(hex::encode(cellscript::ckb_blake2b256(recipe))),
        )
        .unwrap();
        assert_eq!(reproducible.verification_level, "evidence_required");
        assert_eq!(reproducible.artifact_format, "reproducible-binary");
        assert!(reproducible.protocol_bundle_schema.is_none());

        let copy = verify_bundle("copy_material", &[("source", b"starter")], None, None, None).unwrap();
        assert_eq!(copy.verification_level, "hash_bound");
        assert_eq!(copy.artifact_format, "copy-material");
        assert!(copy.artifact_hash.is_none());
        assert!(copy.protocol_bundle_schema.is_none());
    }

    #[test]
    fn rejects_executable_bundle_when_published_hash_does_not_match() {
        let fixture = VerifiedCkbFixture::new();
        let error = verify_bundle(
            "ckb_executable",
            &fixture.objects(),
            Some("11".repeat(32)),
            Some(hex::encode(cellscript::ckb_blake2b256(&fixture.abi))),
            None,
        )
        .unwrap_err();
        assert!(error.to_string().contains("artifact_hash mismatch"));
    }

    #[test]
    fn audited_contract_requires_an_immutable_audit_report_object() {
        let encode = |role: &str| ArtifactBundleObject {
            role: role.to_string(),
            content_base64: base64::engine::general_purpose::STANDARD.encode(role),
        };
        let contract = json!({
            "security": { "status": "audited", "audit_report_hash": "11".repeat(32) }
        });
        let mut bundle = ArtifactBundle {
            schema: "cellscript-registry-bundle".to_string(),
            namespace: "cellscript".to_string(),
            name: "demo".to_string(),
            release: "1.2.3".to_string(),
            profile: "ckb_executable".to_string(),
            manifest_json: contract.to_string(),
            objects: vec![
                encode("source"),
                encode("executable"),
                encode("abi"),
                encode("metadata"),
                encode("lowering_record"),
                encode("source_map"),
            ],
        };

        let error = validate_bundle_roles(&bundle, "ckb_executable", &contract).unwrap_err();
        assert!(error.to_string().contains("audit_report"));

        bundle.objects.push(encode("audit_report"));
        validate_bundle_roles(&bundle, "ckb_executable", &contract).unwrap();
    }

    fn verify_bundle(
        profile: &str,
        objects: &[(&str, &[u8])],
        artifact_hash: Option<String>,
        abi_hash: Option<String>,
        build_recipe_hash: Option<String>,
    ) -> Result<VerificationOutput> {
        let root = tempfile::tempdir().unwrap();
        let kind = match profile {
            "ckb_executable" => "deployable_contract",
            "reproducible_build" => "reproducible_binary",
            "copy_material" => "template",
            _ => unreachable!("test helper only supports generic artifact profiles"),
        };
        let profile_contract = match profile {
            "ckb_executable" => {
                let reproducible = build_recipe_hash.is_some();
                let mut value = json!({
                    "schema": cellscript::package::registry::ARTIFACT_PROFILE_CONTRACT_SCHEMA,
                    "artifact_kind": kind,
                    "profile": profile,
                    "build": {
                        "target": "riscv64imac-unknown-none-elf",
                        "toolchain": "rustc 1.97.1",
                        "profile": "release",
                        "source_revision": "0123456789abcdef",
                        "reproducible": reproducible
                    },
                    "security": { "status": "review_required" },
                    "ckb": {
                        "vm_version": "2",
                        "script_role": "type",
                        "hash_type": "data1",
                        "dep_type": "code",
                        "abi_hash": abi_hash.clone().unwrap()
                    }
                });
                if reproducible {
                    value["reproduction"] = json!({
                        "environment": "docker.io/library/rust:1.97.1@sha256:0123456789abcdef",
                        "command": "cargo build --locked --release",
                        "recipe_hash": build_recipe_hash.clone().unwrap(),
                        "expected_artifact_hash": artifact_hash.clone().unwrap()
                    });
                }
                value
            }
            "reproducible_build" => json!({
                "schema": cellscript::package::registry::ARTIFACT_PROFILE_CONTRACT_SCHEMA,
                "artifact_kind": kind,
                "profile": profile,
                "build": {
                    "target": "x86_64-unknown-linux-gnu",
                    "toolchain": "rustc 1.97.1",
                    "profile": "release",
                    "source_revision": "0123456789abcdef",
                    "reproducible": true
                },
                "security": { "status": "review_required" },
                "reproduction": {
                    "environment": "docker.io/library/rust:1.97.1@sha256:0123456789abcdef",
                    "command": "cargo build --locked --release",
                    "recipe_hash": build_recipe_hash.clone().unwrap(),
                    "expected_artifact_hash": artifact_hash.clone().unwrap()
                }
            }),
            "copy_material" => json!({
                "schema": cellscript::package::registry::ARTIFACT_PROFILE_CONTRACT_SCHEMA,
                "artifact_kind": kind,
                "profile": profile,
                "copy": { "format": "file_map_v1", "entrypoint": "template.cell" }
            }),
            _ => unreachable!(),
        };
        let manifest_json = cellscript::package::registry::canonical_artifact_contract_json(&profile_contract).unwrap();
        let bundle = json!({
            "schema": "cellscript-registry-bundle",
            "namespace": "cellscript",
            "name": "demo",
            "release": "1.2.3",
            "profile": profile,
            "manifest_json": manifest_json,
            "objects": objects.iter().map(|(role, bytes)| json!({
                "role": role,
                "content_base64": base64::engine::general_purpose::STANDARD.encode(bytes),
            })).collect::<Vec<_>>(),
        });
        let path = root.path().join("bundle.json");
        fs::write(&path, serde_json::to_vec(&bundle).unwrap()).unwrap();
        let source = objects.iter().find(|(role, _)| *role == "source").unwrap().1;
        verify(Args {
            snapshot: path,
            namespace: "cellscript".to_string(),
            name: "demo".to_string(),
            version: "1.2.3".to_string(),
            source_hash: hex::encode(cellscript::ckb_blake2b256(source)),
            manifest_hash: hex::encode(cellscript::ckb_blake2b256(manifest_json.as_bytes())),
            artifact_kind: kind.to_string(),
            profile: profile.to_string(),
            compatibility_profile_hash: None,
            interface_hash: None,
            artifact_hash,
            abi_hash,
            build_recipe_hash,
        })
    }
}
