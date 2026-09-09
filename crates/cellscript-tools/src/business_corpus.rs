//! Frozen inventory validation for the 0.30 business-capability corpus.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path};
use std::process::Command;

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

const MANIFEST: &str = "tests/fixtures/business_corpus.json";
const SCHEMA: &str = "cellscript-business-corpus-v1";
const CRYPTO_MATRIX: &str = "tests/fixtures/cryptographic_capability_matrix.json";
const CRYPTO_MATRIX_SCHEMA: &str = "cellscript-cryptographic-capability-matrix-v1";
const CRYPTO_MATRIX_DOCUMENTATION: &str = "docs/CELLSCRIPT_0_30_CRYPTOGRAPHIC_CAPABILITY_MATRIX.md";
const REQUIRED_FAMILIES: [&str; 8] = [
    "authorization",
    "committed_state",
    "external_verifier",
    "fungible_asset",
    "multi_script_composition",
    "nft_dob",
    "order_amm",
    "temporal",
];
const REQUIRED_LAYERS: [&str; 10] = [
    "builder_signing",
    "ckb_vm",
    "deployment_identity",
    "independent_review",
    "measurements",
    "metadata_checker",
    "node_admission",
    "parser_type_ir",
    "simulator",
    "stateful",
];
const REQUIRED_ANCHOR_CAPABILITIES: [&str; 7] = [
    "authenticated_cell_dep",
    "bounded_group_inputs",
    "bounded_output_plan",
    "fungible_conservation",
    "lock_authorization",
    "multiple_type_and_lock_groups",
    "persistent_multi_action_policy",
];
const REQUIRED_RELEASE_GATES: [&str; 7] = ["backend", "ci", "deployment", "dev", "independent_review", "node_admission", "release"];
const REQUIRED_CRYPTO_CAPABILITIES: [&str; 10] = [
    "canonical-script-hash",
    "ckb-blake2b-256",
    "exact-bip340-verifier",
    "exact-script-handle",
    "raw-transaction-hash",
    "sha256-and-sha256d",
    "sha256d-merkle-opening",
    "standard-multisig-lock",
    "trusted-external-delegation",
    "zero-lock-sighash-all",
];
const REQUIRED_CRYPTO_DOMAINS: [&str; 12] = [
    "address",
    "authenticated-opening",
    "bip340-public-key-encoding",
    "bip340-signature-encoding",
    "bounded-witness-bytes",
    "commitment-root",
    "exact-script-handle",
    "raw-hash",
    "script",
    "script-hash",
    "sighash-all-digest",
    "verification-result",
];
const REQUIRED_CRYPTO_RELEASE_GATES: [&str; 3] = ["independent_review", "release_gate", "selected_network_deployment"];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Corpus {
    schema: String,
    status: String,
    claim: String,
    families: Vec<Family>,
    anchor: Anchor,
    cryptographic_capability_matrix: String,
    release_requirements: BTreeMap<String, String>,
    #[serde(default)]
    evidence_files: Vec<String>,
    #[serde(default)]
    inventory_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CryptographicCapabilityMatrix {
    schema: String,
    status: String,
    scope: String,
    claim: String,
    documentation: String,
    domains: Vec<CryptographicDomain>,
    capabilities: Vec<CryptographicCapability>,
    deferred: Vec<String>,
    release_requirements: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CryptographicDomain {
    id: String,
    source_type: String,
    enforcement: String,
    evidence: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CryptographicCapability {
    id: String,
    classification: String,
    status: String,
    apis: Vec<String>,
    algorithms: Vec<String>,
    input_domains: Vec<String>,
    output_domain: String,
    bounds: Vec<String>,
    failure_codes: Vec<u16>,
    witness_owner: String,
    families: Vec<String>,
    ckb_vm_evidence: Vec<String>,
    checker_evidence: Vec<String>,
    measurement_status: String,
    measurement_evidence: Vec<String>,
    dependency_identity_evidence: Vec<String>,
    boundary: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Family {
    id: String,
    scenarios: Vec<String>,
    required_capabilities: Vec<String>,
    sources: Vec<String>,
    transaction_fixtures: Vec<String>,
    positive_cases: Vec<String>,
    adversarial_cases: Vec<String>,
    reference: ReferenceBoundary,
    evidence_layers: BTreeMap<String, EvidenceLayer>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReferenceBoundary {
    kind: String,
    identity: String,
    paths: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceLayer {
    status: String,
    paths: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Anchor {
    id: String,
    sources: Vec<String>,
    transaction_fixture: String,
    execution_test: String,
    protocol_bundle_evidence: Vec<String>,
    builder_evidence: Vec<String>,
    required_capabilities: Vec<String>,
    positive_cases: Vec<String>,
    adversarial_cases: Vec<String>,
    artifacts: u64,
    script_groups: u64,
}

fn collect_evidence(corpus: &Corpus, matrix: &CryptographicCapabilityMatrix) -> BTreeSet<String> {
    let mut paths = BTreeSet::new();
    for family in &corpus.families {
        paths.extend(family.sources.iter().cloned());
        paths.extend(family.transaction_fixtures.iter().cloned());
        paths.extend(family.reference.paths.iter().cloned());
        for layer in family.evidence_layers.values() {
            paths.extend(layer.paths.iter().cloned());
        }
    }
    paths.extend(corpus.anchor.sources.iter().cloned());
    paths.insert(corpus.anchor.transaction_fixture.clone());
    paths.insert(corpus.anchor.execution_test.clone());
    paths.extend(corpus.anchor.protocol_bundle_evidence.iter().cloned());
    paths.extend(corpus.anchor.builder_evidence.iter().cloned());
    paths.insert(corpus.cryptographic_capability_matrix.clone());
    paths.insert(matrix.documentation.clone());
    for domain in &matrix.domains {
        paths.extend(domain.evidence.iter().cloned());
    }
    for capability in &matrix.capabilities {
        paths.extend(capability.ckb_vm_evidence.iter().cloned());
        paths.extend(capability.checker_evidence.iter().cloned());
        paths.extend(capability.measurement_evidence.iter().cloned());
        paths.extend(capability.dependency_identity_evidence.iter().cloned());
    }
    paths
}

fn load_crypto_matrix(root: &Path, corpus: &Corpus) -> Result<CryptographicCapabilityMatrix> {
    if corpus.cryptographic_capability_matrix != CRYPTO_MATRIX {
        bail!("business corpus cryptographic capability matrix must be {CRYPTO_MATRIX}");
    }
    let bytes = fs::read(root.join(CRYPTO_MATRIX)).with_context(|| format!("failed to read {CRYPTO_MATRIX}"))?;
    serde_json::from_slice(&bytes).with_context(|| format!("invalid {CRYPTO_MATRIX}"))
}

fn validate_crypto_matrix(matrix: &CryptographicCapabilityMatrix, release: bool) -> Result<()> {
    if matrix.schema != CRYPTO_MATRIX_SCHEMA {
        bail!("cryptographic capability matrix schema must be {CRYPTO_MATRIX_SCHEMA}");
    }
    if !matches!(matrix.status.as_str(), "candidate" | "accepted") {
        bail!("cryptographic capability matrix status must be candidate or accepted");
    }
    if matrix.scope.trim().is_empty() || matrix.claim.trim().is_empty() {
        bail!("cryptographic capability matrix scope and claim must be explicit");
    }
    if matrix.documentation != CRYPTO_MATRIX_DOCUMENTATION {
        bail!("cryptographic capability matrix documentation must be {CRYPTO_MATRIX_DOCUMENTATION}");
    }
    validate_nonempty(&matrix.deferred, "cryptographic capability matrix deferred boundaries")?;

    let domain_ids = matrix.domains.iter().map(|domain| domain.id.as_str()).collect::<BTreeSet<_>>();
    if domain_ids != REQUIRED_CRYPTO_DOMAINS.into_iter().collect() || matrix.domains.len() != REQUIRED_CRYPTO_DOMAINS.len() {
        bail!("cryptographic capability matrix must contain each required value domain exactly once");
    }
    for domain in &matrix.domains {
        if domain.source_type.trim().is_empty() || domain.enforcement.trim().is_empty() {
            bail!("cryptographic value domain {} must define its source type and enforcement", domain.id);
        }
        validate_nonempty(&domain.evidence, &format!("cryptographic value domain {} evidence", domain.id))?;
    }

    let capability_ids = matrix.capabilities.iter().map(|capability| capability.id.as_str()).collect::<BTreeSet<_>>();
    if capability_ids != REQUIRED_CRYPTO_CAPABILITIES.into_iter().collect()
        || matrix.capabilities.len() != REQUIRED_CRYPTO_CAPABILITIES.len()
    {
        bail!("cryptographic capability matrix must contain each required portfolio capability exactly once");
    }
    let family_ids = REQUIRED_FAMILIES.into_iter().collect::<BTreeSet<_>>();
    let mut covered_families = BTreeSet::new();
    for capability in &matrix.capabilities {
        if !matches!(capability.classification.as_str(), "native" | "checked-identity" | "exact-standard-lock" | "trusted-external") {
            bail!("cryptographic capability {} has an invalid classification", capability.id);
        }
        if !matches!(capability.status.as_str(), "executable" | "composition-boundary") {
            bail!("cryptographic capability {} has an invalid status", capability.id);
        }
        validate_nonempty(&capability.apis, &format!("cryptographic capability {} APIs", capability.id))?;
        validate_nonempty(&capability.algorithms, &format!("cryptographic capability {} algorithms", capability.id))?;
        validate_nonempty(&capability.input_domains, &format!("cryptographic capability {} input domains", capability.id))?;
        validate_nonempty(&capability.bounds, &format!("cryptographic capability {} bounds", capability.id))?;
        validate_nonempty(&capability.families, &format!("cryptographic capability {} families", capability.id))?;
        validate_nonempty(&capability.ckb_vm_evidence, &format!("cryptographic capability {} CKB-VM evidence", capability.id))?;
        validate_nonempty(&capability.checker_evidence, &format!("cryptographic capability {} checker evidence", capability.id))?;
        if !matches!(capability.measurement_status.as_str(), "passed" | "release-candidate-required") {
            bail!("cryptographic capability {} has an invalid measurement status", capability.id);
        }
        validate_nonempty(
            &capability.measurement_evidence,
            &format!("cryptographic capability {} measurement evidence", capability.id),
        )?;
        validate_nonempty(
            &capability.dependency_identity_evidence,
            &format!("cryptographic capability {} dependency identity evidence", capability.id),
        )?;
        if capability.failure_codes.is_empty() || capability.witness_owner.trim().is_empty() || capability.boundary.trim().is_empty() {
            bail!("cryptographic capability {} must define failures, witness ownership, and its proof boundary", capability.id);
        }
        if !capability.input_domains.iter().all(|domain| domain_ids.contains(domain.as_str()))
            || !domain_ids.contains(capability.output_domain.as_str())
        {
            bail!("cryptographic capability {} references an unknown value domain", capability.id);
        }
        for family in &capability.families {
            if !family_ids.contains(family.as_str()) {
                bail!("cryptographic capability {} references unknown business family {family}", capability.id);
            }
            covered_families.insert(family.as_str());
        }
        if release && capability.measurement_status != "passed" {
            bail!("release cryptographic capability {} still requires maximum-bound measurements", capability.id);
        }
    }
    if covered_families != family_ids {
        bail!("cryptographic capability matrix does not cover every business family");
    }

    let release_gates = matrix.release_requirements.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if release_gates != REQUIRED_CRYPTO_RELEASE_GATES.into_iter().collect() {
        bail!("cryptographic capability matrix must classify every release requirement");
    }
    for (gate, status) in &matrix.release_requirements {
        if !matches!(status.as_str(), "passed" | "pending" | "not-authorized") {
            bail!("cryptographic capability matrix release requirement {gate} has an invalid status");
        }
        if release && status != "passed" {
            bail!("release cryptographic capability matrix is incomplete: {gate} is {status}");
        }
    }
    if release && matrix.status != "accepted" {
        bail!("release cryptographic capability matrix status must be accepted");
    }
    Ok(())
}

fn inventory_digest(root: &Path, paths: &BTreeSet<String>) -> Result<String> {
    let mut digest = Sha256::new();
    for relative in paths {
        let bytes = fs::read(root.join(relative)).with_context(|| format!("failed to read corpus evidence {relative}"))?;
        digest.update((relative.len() as u64).to_le_bytes());
        digest.update(relative.as_bytes());
        digest.update((bytes.len() as u64).to_le_bytes());
        digest.update(bytes);
    }
    Ok(format!("0x{}", hex::encode(digest.finalize())))
}

fn tracked_files(root: &Path) -> Result<BTreeSet<String>> {
    let output = Command::new("git")
        .args(["ls-files", "--recurse-submodules", "-z"])
        .current_dir(root)
        .output()
        .context("failed to enumerate tracked corpus evidence")?;
    if !output.status.success() {
        bail!("git ls-files --recurse-submodules failed: {}", String::from_utf8_lossy(&output.stderr).trim());
    }
    output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|bytes| !bytes.is_empty())
        .map(|bytes| String::from_utf8(bytes.to_vec()).context("tracked corpus path is not UTF-8"))
        .collect()
}

fn validate_path(root: &Path, tracked: &BTreeSet<String>, relative: &str) -> Result<()> {
    let path = Path::new(relative);
    if path.is_absolute() || path.components().any(|component| !matches!(component, Component::Normal(_))) || relative.contains('\\') {
        bail!("corpus evidence path is not normalized and repository-relative: {relative}");
    }
    let full = root.join(path);
    let metadata = fs::symlink_metadata(&full).with_context(|| format!("corpus evidence is missing: {relative}"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        bail!("corpus evidence must be a regular non-symlink file: {relative}");
    }
    let canonical = full.canonicalize().with_context(|| format!("failed to canonicalize corpus evidence: {relative}"))?;
    if !canonical.starts_with(root.canonicalize()?) {
        bail!("corpus evidence escapes the repository: {relative}");
    }
    if !tracked.contains(relative) {
        bail!("corpus evidence is not tracked by Git: {relative}");
    }
    Ok(())
}

fn validate_nonempty(values: &[String], label: &str) -> Result<()> {
    if values.is_empty() || values.iter().any(|value| value.trim().is_empty()) {
        bail!("{label} must contain nonempty entries");
    }
    let unique = values.iter().collect::<BTreeSet<_>>();
    if unique.len() != values.len() {
        bail!("{label} contains duplicates");
    }
    Ok(())
}

fn validate(root: &Path, corpus: &Corpus, matrix: &CryptographicCapabilityMatrix, release: bool) -> Result<()> {
    if corpus.schema != SCHEMA {
        bail!("business corpus schema must be {SCHEMA}");
    }
    if !matches!(corpus.status.as_str(), "candidate" | "accepted") {
        bail!("business corpus status must be candidate or accepted");
    }
    if corpus.claim.trim().is_empty() {
        bail!("business corpus claim must be explicit");
    }
    validate_crypto_matrix(matrix, release)?;
    let family_ids = corpus.families.iter().map(|family| family.id.as_str()).collect::<BTreeSet<_>>();
    if family_ids != REQUIRED_FAMILIES.into_iter().collect() || corpus.families.len() != REQUIRED_FAMILIES.len() {
        bail!("business corpus must contain each required family exactly once");
    }
    for family in &corpus.families {
        validate_nonempty(&family.scenarios, &format!("{} scenarios", family.id))?;
        validate_nonempty(&family.required_capabilities, &format!("{} required_capabilities", family.id))?;
        validate_nonempty(&family.sources, &format!("{} sources", family.id))?;
        validate_nonempty(&family.transaction_fixtures, &format!("{} transaction_fixtures", family.id))?;
        validate_nonempty(&family.positive_cases, &format!("{} positive_cases", family.id))?;
        validate_nonempty(&family.adversarial_cases, &format!("{} adversarial_cases", family.id))?;
        if !matches!(family.reference.kind.as_str(), "matched-rust" | "pinned-standard-script" | "exact-trusted-external")
            || family.reference.identity.trim().is_empty()
        {
            bail!("{} has an invalid reference boundary", family.id);
        }
        validate_nonempty(&family.reference.paths, &format!("{} reference paths", family.id))?;
        let layers = family.evidence_layers.keys().map(String::as_str).collect::<BTreeSet<_>>();
        if layers != REQUIRED_LAYERS.into_iter().collect() {
            bail!("{} must classify every required evidence layer exactly once", family.id);
        }
        for (name, layer) in &family.evidence_layers {
            if !matches!(layer.status.as_str(), "passed" | "not-applicable" | "pending" | "release-candidate-required") {
                bail!("{} evidence layer {name} has an invalid status", family.id);
            }
            if layer.status == "passed" {
                validate_nonempty(&layer.paths, &format!("{} passed {name} evidence", family.id))?;
            }
            if release && !matches!(layer.status.as_str(), "passed" | "not-applicable") {
                bail!("release corpus is incomplete: {} evidence layer {name} is {}", family.id, layer.status);
            }
        }
    }

    if corpus.anchor.id != "authenticated-partial-settlement"
        || corpus.anchor.artifacts < 4
        || corpus.anchor.script_groups < 5
        || corpus.anchor.sources.len() < 4
    {
        bail!("business corpus anchor does not meet the multi-artifact composition boundary");
    }
    validate_nonempty(&corpus.anchor.positive_cases, "anchor positive_cases")?;
    validate_nonempty(&corpus.anchor.adversarial_cases, "anchor adversarial_cases")?;
    validate_nonempty(&corpus.anchor.protocol_bundle_evidence, "anchor protocol_bundle_evidence")?;
    validate_nonempty(&corpus.anchor.builder_evidence, "anchor builder_evidence")?;
    let capabilities = corpus.anchor.required_capabilities.iter().map(String::as_str).collect::<BTreeSet<_>>();
    if !REQUIRED_ANCHOR_CAPABILITIES.into_iter().all(|capability| capabilities.contains(capability)) {
        bail!("business corpus anchor is missing a required cross-feature capability");
    }

    let release_gates = corpus.release_requirements.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if release_gates != REQUIRED_RELEASE_GATES.into_iter().collect() {
        bail!("business corpus release_requirements must classify every required gate");
    }
    for (gate, status) in &corpus.release_requirements {
        if !matches!(status.as_str(), "passed" | "pending" | "not-authorized") {
            bail!("business corpus release requirement {gate} has an invalid status");
        }
        if release && status != "passed" {
            bail!("release corpus is incomplete: release requirement {gate} is {status}");
        }
    }
    if release && corpus.status != "accepted" {
        bail!("release corpus status must be accepted");
    }

    let evidence = collect_evidence(corpus, matrix);
    let declared = corpus.evidence_files.iter().cloned().collect::<BTreeSet<_>>();
    if declared.len() != corpus.evidence_files.len() || declared != evidence {
        bail!("business corpus evidence_files is stale; run check-business-corpus --write");
    }
    let tracked = tracked_files(root)?;
    for relative in &evidence {
        validate_path(root, &tracked, relative)?;
    }
    let digest = inventory_digest(root, &evidence)?;
    if corpus.inventory_sha256 != digest {
        bail!("business corpus inventory digest is stale; expected {digest}; run check-business-corpus --write");
    }
    println!(
        "{}",
        serde_json::json!({
            "schema": corpus.schema,
            "status": corpus.status,
            "families": corpus.families.len(),
            "evidence_files": evidence.len(),
            "inventory_sha256": digest,
            "release_ready": release,
        })
    );
    Ok(())
}

pub fn run(root: &Path, write: bool, release: bool) -> Result<()> {
    if write && release {
        bail!("--write and --release cannot be used together");
    }
    let path = root.join(MANIFEST);
    let bytes = fs::read(&path).with_context(|| format!("failed to read {MANIFEST}"))?;
    let mut value: Value = serde_json::from_slice(&bytes).with_context(|| format!("failed to parse {MANIFEST}"))?;
    let mut corpus: Corpus = serde_json::from_value(value.clone()).with_context(|| format!("invalid {MANIFEST}"))?;
    let matrix = load_crypto_matrix(root, &corpus)?;
    if write {
        let evidence = collect_evidence(&corpus, &matrix);
        value["evidence_files"] = serde_json::to_value(evidence.iter().collect::<Vec<_>>())?;
        value["inventory_sha256"] = Value::String(inventory_digest(root, &evidence)?);
        let mut output = serde_json::to_vec_pretty(&value)?;
        output.push(b'\n');
        fs::write(&path, output).with_context(|| format!("failed to update {MANIFEST}"))?;
        corpus = serde_json::from_value(value)?;
    }
    validate(root, &corpus, &matrix, release)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matrix() -> CryptographicCapabilityMatrix {
        serde_json::from_str(include_str!("../../../tests/fixtures/cryptographic_capability_matrix.json"))
            .expect("checked-in cryptographic capability matrix")
    }

    #[test]
    fn cryptographic_matrix_rejects_removed_rows_unknown_domains_and_premature_release() {
        let mut missing = matrix();
        missing.capabilities.pop();
        assert!(validate_crypto_matrix(&missing, false).unwrap_err().to_string().contains("each required portfolio capability"));

        let mut unknown_domain = matrix();
        unknown_domain.capabilities[0].output_domain = "unclassified-bytes".to_string();
        assert!(validate_crypto_matrix(&unknown_domain, false).unwrap_err().to_string().contains("unknown value domain"));

        let candidate = matrix();
        assert!(validate_crypto_matrix(&candidate, true).unwrap_err().to_string().contains("maximum-bound measurements"));
    }
}
