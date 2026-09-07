use cellscript::{
    compile_path_with_executable_surface_policy, compile_with_executable_surface_policy, strip_vm_abi_trailer, CellScriptEdition,
    CompileEntryScope, CompileOptions, CompileResult, ExecutableSurfacePolicy,
};
use cellscript_artifact_checker::{
    canonical_hash, check_bundle_values, CheckerBudgets, CheckerRejectionCode, SourceArtifactMap, VerifiedLoweringRecord,
    LOWERING_RECORD_SCHEMA, SOURCE_MAP_SCHEMA, TYPED_SEMANTICS_SCHEMA,
};
use ckb_testtool::{builtin::ALWAYS_SUCCESS, ckb_types::bytes::Bytes};
use serde_json::Value;

#[path = "support/ckb_script_runner.rs"]
#[allow(dead_code)]
mod ckb_script_runner;

use ckb_script_runner::{build_simple_fixture, execute_cellscript_script, FixtureCell};

fn hash_literal(hash: &[u8; 32]) -> String {
    hash.iter().map(|byte| format!("\\x{byte:02x}")).collect()
}

fn source(hash: &[u8; 32], trusted: bool) -> String {
    let name = if trusted { "trusted_exec_cell_dep_u8_args" } else { "exec_cell_dep_u8_args" };
    let hash_argument = if trusted { format!("Hash::from_bytes(b\"{}\"), ", hash_literal(hash)) } else { String::new() };
    format!(
        r#"module trusted_external

action verify() -> u64 {{
    verification
    ckb::{name}(0, {hash_argument}0, 0, 0, 0, 0)
    require false
    return 0
}}
"#
    )
}

fn spawn_source(hash: &[u8; 32]) -> String {
    format!(
        r#"module trusted_external_spawn

action verify() -> u64 {{
    verification
    let mut bytes = Vec::new()
    bytes.push(0 as u8)
    ckb::trusted_spawn_wait_cell_dep_hex4(
        0,
        Hash::from_bytes(b"{}"),
        bytes,
        1,
        0,
        0,
        0
    )
    return 0
}}
"#,
        hash_literal(hash)
    )
}

fn helper_source(hash: &[u8; 32]) -> String {
    format!(
        r#"module trusted_external_helper

fn delegate() -> u64 {{
    ckb::trusted_exec_cell_dep_u8_args(
        0,
        Hash::from_bytes(b"{}"),
        0,
        0,
        0,
        0,
        0
    )
    return 0
}}

action verify() -> u64 {{ return delegate() }}
"#,
        hash_literal(hash)
    )
}

fn lock_source(hash: &[u8; 32]) -> String {
    format!(
        r#"module trusted_external_lock

lock delegate() -> bool {{
    verification
    ckb::trusted_exec_cell_dep_u8_args(
        0,
        Hash::from_bytes(b"{}"),
        0,
        0,
        0,
        0,
        0
    )
    return false
}}
"#,
        hash_literal(hash)
    )
}

fn options(edition: CellScriptEdition) -> CompileOptions {
    CompileOptions { edition, target: Some("riscv64-elf".to_string()), target_profile: Some("ckb".to_string()), ..Default::default() }
}

fn compile_package(hash: &[u8; 32], declared_hash: &[u8; 32]) -> Result<CompileResult, cellscript::error::CompileError> {
    compile_package_for_edition(hash, declared_hash, CellScriptEdition::Edition2027)
}

fn compile_package_for_edition(
    hash: &[u8; 32],
    declared_hash: &[u8; 32],
    edition: CellScriptEdition,
) -> Result<CompileResult, cellscript::error::CompileError> {
    let directory = tempfile::tempdir().unwrap();
    let root = camino::Utf8Path::from_path(directory.path()).unwrap();
    let manager = cellscript::package::PackageManager::new(directory.path());
    manager.init("trusted_external").unwrap();
    let mut manifest = manager.read_manifest().unwrap();
    manifest.package.edition = edition;
    manifest.deploy.ckb = Some(cellscript::package::CkbDeployConfig {
        trusted_external_verifiers: vec![cellscript::package::CkbTrustedExternalVerifierConfig {
            schema: "cellscript-trusted-external-verifier-v1".to_string(),
            name: "always-success-fixture".to_string(),
            scope: "action:verify".to_string(),
            operation: "exec".to_string(),
            adapter: "u8-args-v1".to_string(),
            code_hash: cellscript_artifact_checker::hex_encode(declared_hash),
            hash_type: "data".to_string(),
            source_identity: "ckb-testtool::builtin::ALWAYS_SUCCESS".to_string(),
            applicability: "test-only EXEC process-replacement target".to_string(),
            trust_basis: "pinned ckb-testtool fixture bytes exercised in CKB-VM".to_string(),
            guarantees: vec!["returns success for the bounded test invocation".to_string()],
        }],
        ..Default::default()
    });
    manager.write_manifest(&manifest).unwrap();
    std::fs::write(root.join("src/main.cell"), source(hash, true)).unwrap();
    compile_path_with_executable_surface_policy(
        root,
        options(edition),
        Some(CompileEntryScope::Action("verify".to_string())),
        ExecutableSurfacePolicy::DenyFailClosed,
    )
}

fn compile_spawn_package(hash: &[u8; 32]) -> CompileResult {
    let directory = tempfile::tempdir().unwrap();
    let root = camino::Utf8Path::from_path(directory.path()).unwrap();
    let manager = cellscript::package::PackageManager::new(directory.path());
    manager.init("trusted_external_spawn").unwrap();
    let mut manifest = manager.read_manifest().unwrap();
    manifest.package.edition = CellScriptEdition::Edition2027;
    manifest.deploy.ckb = Some(cellscript::package::CkbDeployConfig {
        trusted_external_verifiers: vec![cellscript::package::CkbTrustedExternalVerifierConfig {
            schema: "cellscript-trusted-external-verifier-v1".to_string(),
            name: "always-success-spawn-fixture".to_string(),
            scope: "action:verify".to_string(),
            operation: "spawn-wait".to_string(),
            adapter: "hex4-v1".to_string(),
            code_hash: cellscript_artifact_checker::hex_encode(hash),
            hash_type: "data".to_string(),
            source_identity: "ckb-testtool::builtin::ALWAYS_SUCCESS".to_string(),
            applicability: "test-only SPAWN/WAIT child".to_string(),
            trust_basis: "pinned ckb-testtool fixture bytes exercised in CKB-VM".to_string(),
            guarantees: vec!["returns a zero child exit status for the empty four-argument invocation".to_string()],
        }],
        ..Default::default()
    });
    manager.write_manifest(&manifest).unwrap();
    std::fs::write(root.join("src/main.cell"), spawn_source(hash)).unwrap();
    compile_path_with_executable_surface_policy(
        root,
        options(CellScriptEdition::Edition2027),
        Some(CompileEntryScope::Action("verify".to_string())),
        ExecutableSurfacePolicy::DenyFailClosed,
    )
    .unwrap()
}

fn compile_helper_package(hash: &[u8; 32]) -> CompileResult {
    let directory = tempfile::tempdir().unwrap();
    let root = camino::Utf8Path::from_path(directory.path()).unwrap();
    let manager = cellscript::package::PackageManager::new(directory.path());
    manager.init("trusted_external_helper").unwrap();
    let mut manifest = manager.read_manifest().unwrap();
    manifest.package.edition = CellScriptEdition::Edition2027;
    manifest.deploy.ckb = Some(cellscript::package::CkbDeployConfig {
        trusted_external_verifiers: vec![cellscript::package::CkbTrustedExternalVerifierConfig {
            schema: "cellscript-trusted-external-verifier-v1".to_string(),
            name: "helper-delegate".to_string(),
            scope: "helper:delegate".to_string(),
            operation: "exec".to_string(),
            adapter: "u8-args-v1".to_string(),
            code_hash: cellscript_artifact_checker::hex_encode(hash),
            hash_type: "data".to_string(),
            source_identity: "ckb-testtool::builtin::ALWAYS_SUCCESS".to_string(),
            applicability: "test-only helper delegation".to_string(),
            trust_basis: "pinned fixture bytes".to_string(),
            guarantees: vec!["returns success for the bounded invocation".to_string()],
        }],
        ..Default::default()
    });
    manager.write_manifest(&manifest).unwrap();
    std::fs::write(root.join("src/main.cell"), helper_source(hash)).unwrap();
    compile_path_with_executable_surface_policy(
        root,
        options(CellScriptEdition::Edition2027),
        Some(CompileEntryScope::Action("verify".to_string())),
        ExecutableSurfacePolicy::DenyFailClosed,
    )
    .unwrap()
}

fn compile_lock_package(hash: &[u8; 32]) -> CompileResult {
    let directory = tempfile::tempdir().unwrap();
    let root = camino::Utf8Path::from_path(directory.path()).unwrap();
    let manager = cellscript::package::PackageManager::new(directory.path());
    manager.init("trusted_external_lock").unwrap();
    let mut manifest = manager.read_manifest().unwrap();
    manifest.package.edition = CellScriptEdition::Edition2027;
    let mut trusted = declaration(hash);
    trusted.name = "lock-delegate".to_string();
    trusted.scope = "lock:delegate".to_string();
    trusted.applicability = "test-only lock delegation".to_string();
    manifest.deploy.ckb =
        Some(cellscript::package::CkbDeployConfig { trusted_external_verifiers: vec![trusted], ..Default::default() });
    manager.write_manifest(&manifest).unwrap();
    std::fs::write(root.join("src/main.cell"), lock_source(hash)).unwrap();
    compile_path_with_executable_surface_policy(
        root,
        options(CellScriptEdition::Edition2027),
        Some(CompileEntryScope::Lock("delegate".to_string())),
        ExecutableSurfacePolicy::DenyFailClosed,
    )
    .unwrap()
}

fn compile_custom_package(
    package_source: &str,
    declarations: Vec<cellscript::package::CkbTrustedExternalVerifierConfig>,
) -> Result<CompileResult, cellscript::error::CompileError> {
    let directory = tempfile::tempdir().unwrap();
    let root = camino::Utf8Path::from_path(directory.path()).unwrap();
    let manager = cellscript::package::PackageManager::new(directory.path());
    manager.init("trusted_external_custom").unwrap();
    let mut manifest = manager.read_manifest().unwrap();
    manifest.package.edition = CellScriptEdition::Edition2027;
    manifest.deploy.ckb =
        Some(cellscript::package::CkbDeployConfig { trusted_external_verifiers: declarations, ..Default::default() });
    manager.write_manifest(&manifest).unwrap();
    std::fs::write(root.join("src/main.cell"), package_source).unwrap();
    compile_path_with_executable_surface_policy(
        root,
        options(CellScriptEdition::Edition2027),
        Some(CompileEntryScope::Action("verify".to_string())),
        ExecutableSurfacePolicy::DenyFailClosed,
    )
}

fn declaration(hash: &[u8; 32]) -> cellscript::package::CkbTrustedExternalVerifierConfig {
    cellscript::package::CkbTrustedExternalVerifierConfig {
        schema: "cellscript-trusted-external-verifier-v1".to_string(),
        name: "bounded-external".to_string(),
        scope: "action:verify".to_string(),
        operation: "exec".to_string(),
        adapter: "u8-args-v1".to_string(),
        code_hash: cellscript_artifact_checker::hex_encode(hash),
        hash_type: "data".to_string(),
        source_identity: "exact fixture bytes".to_string(),
        applicability: "bounded test delegation".to_string(),
        trust_basis: "fixture hash and CKB-VM execution".to_string(),
        guarantees: vec!["returns success for the declared input domain".to_string()],
    }
}

fn rebind(record: &mut VerifiedLoweringRecord, source_map: &mut SourceArtifactMap, metadata: &mut Value) {
    record.typed_semantics_hash = canonical_hash(TYPED_SEMANTICS_SCHEMA, &record.typed_semantics).unwrap();
    metadata["typed_semantics"] = serde_json::to_value(&record.typed_semantics).unwrap();
    let trusted = serde_json::to_value(&record.typed_semantics.trusted_external_verifiers).unwrap();
    metadata["runtime"]["trusted_external_verifiers"] = trusted.clone();
    metadata["constraints"]["ckb"]["trusted_external_verifiers"] = trusted;
    metadata["typed_semantics_hash"] = Value::String(record.typed_semantics_hash.clone());
    let record_hash = canonical_hash(LOWERING_RECORD_SCHEMA, record).unwrap();
    source_map.lowering_record_hash = record_hash.clone();
    let source_map_hash = canonical_hash(SOURCE_MAP_SCHEMA, source_map).unwrap();
    let bundle_id = canonical_hash(
        "cellscript-verified-bundle-id-v1",
        &(
            record.artifact_hash.as_str(),
            record.typed_semantics_hash.as_str(),
            record.compatibility_profile_hash.as_str(),
            record_hash.as_str(),
            source_map_hash.as_str(),
            source_map.source_digest.as_str(),
        ),
    )
    .unwrap();
    metadata["verified_artifact"]["lowering_record_hash"] = Value::String(record_hash);
    metadata["verified_artifact"]["source_map_hash"] = Value::String(source_map_hash);
    metadata["verified_artifact"]["verified_bundle_id"] = Value::String(bundle_id);
}

#[test]
fn trusted_external_is_explicit_hash_bound_and_executes_in_ckb_vm() {
    let hash = cellscript_artifact_checker::ckb_blake2b256(ALWAYS_SUCCESS.as_ref());
    let result = compile_package(&hash, &hash).unwrap();
    result.validate().unwrap();
    let verifier = &result.metadata.runtime.trusted_external_verifiers[0];
    assert_eq!(verifier.evidence_tier, "trusted-external");
    assert!(!verifier.compiler_proves_internal_semantics);
    assert!(result.metadata.runtime.proof_plan.iter().any(|plan| {
        plan.origin == "action:verify"
            && plan.category == "exec-delegation"
            && plan.evidence_tier == cellscript::EvidenceTier::TrustedExternal
            && plan.on_chain_checked
    }));
    let ckb = result.metadata.constraints.ckb.as_ref().unwrap();
    assert_eq!(ckb.trusted_external_verifiers, result.metadata.runtime.trusted_external_verifiers);
    assert!(ckb.script_references.iter().any(|reference| {
        reference.scope == "action:verify"
            && reference.purpose == "trusted-external-exec"
            && reference.code_hash.as_deref() == Some(verifier.code_hash.as_str())
            && reference.hash_type.as_deref() == Some("data")
    }));
    assert!(result.metadata.runtime.transaction_runtime_input_requirements.iter().any(|requirement| {
        requirement.scope == "action:verify"
            && requirement.status == "trusted-external"
            && requirement.blocker.is_none()
            && requirement.abi == "runtime-load-cell-data-hash-before-delegation-v1"
    }));
    assert_eq!(result.metadata.runtime.proof_plan_soundness.status, "passed");
    let formatted = cellscript::fmt::format_default(&result.ast).unwrap();
    assert!(formatted.contains("ckb::trusted_exec_cell_dep_u8_args("));
    let tokens = cellscript::lexer::lex(&formatted).unwrap();
    cellscript::parser::parse(&tokens).unwrap();

    let mut fixture = build_simple_fixture(Bytes::new(), 1, 1);
    fixture.current_type_script_input_indices = vec![0];
    fixture.cell_deps = vec![FixtureCell { capacity: 100_000_000_000, type_script: None, data: ALWAYS_SUCCESS.clone() }];
    let execution = execute_cellscript_script(strip_vm_abi_trailer(&result.artifact_bytes), &fixture);
    assert_eq!(execution.exit_code, 0, "{:?}", execution.captured_debug);

    fixture.cell_deps[0].data = Bytes::from_static(b"not-the-declared-verifier");
    let rejected = execute_cellscript_script(strip_vm_abi_trailer(&result.artifact_bytes), &fixture);
    assert_ne!(rejected.exit_code, 0, "a different CellDep must fail before EXEC");
}

#[test]
fn trusted_external_package_binding_is_source_edition_independent() {
    let hash = cellscript_artifact_checker::ckb_blake2b256(ALWAYS_SUCCESS.as_ref());
    for edition in [CellScriptEdition::Edition2026, CellScriptEdition::Edition2027] {
        let result = compile_package_for_edition(&hash, &hash, edition).unwrap();
        result.validate().unwrap();
        assert_eq!(result.metadata.edition, edition);
        assert_eq!(result.metadata.runtime.trusted_external_verifiers[0].evidence_tier, "trusted-external");
    }
}

#[test]
fn trusted_external_spawn_wait_binds_hash_and_checks_child_exit() {
    let hash = cellscript_artifact_checker::ckb_blake2b256(ALWAYS_SUCCESS.as_ref());
    let result = compile_spawn_package(&hash);
    result.validate().unwrap();
    assert!(result.metadata.runtime.proof_plan.iter().any(|plan| {
        plan.origin == "action:verify"
            && plan.category == "spawn-delegation"
            && plan.evidence_tier == cellscript::EvidenceTier::TrustedExternal
            && plan.on_chain_checked
    }));

    let mut fixture = build_simple_fixture(Bytes::new(), 1, 1);
    fixture.current_type_script_input_indices = vec![0];
    fixture.cell_deps = vec![FixtureCell { capacity: 100_000_000_000, type_script: None, data: ALWAYS_SUCCESS.clone() }];
    let execution = execute_cellscript_script(strip_vm_abi_trailer(&result.artifact_bytes), &fixture);
    assert_eq!(execution.exit_code, 0, "{:?}", execution.captured_debug);

    fixture.cell_deps[0].data = Bytes::from_static(b"not-the-declared-verifier");
    let rejected = execute_cellscript_script(strip_vm_abi_trailer(&result.artifact_bytes), &fixture);
    assert_ne!(rejected.exit_code, 0, "a different child must fail before SPAWN");
}

#[test]
fn trusted_external_helper_scope_uses_the_typed_helper_identity() {
    let hash = cellscript_artifact_checker::ckb_blake2b256(ALWAYS_SUCCESS.as_ref());
    let result = compile_helper_package(&hash);
    result.validate().unwrap();
    assert_eq!(result.metadata.runtime.trusted_external_verifiers[0].scope, "helper:delegate");
    assert!(result.metadata.functions.iter().any(|function| {
        function.name == "delegate"
            && function
                .proof_plan
                .iter()
                .any(|plan| plan.evidence_tier == cellscript::EvidenceTier::TrustedExternal && plan.on_chain_checked)
    }));
}

#[test]
fn trusted_external_lock_scope_uses_the_selected_lock_identity() {
    let hash = cellscript_artifact_checker::ckb_blake2b256(ALWAYS_SUCCESS.as_ref());
    let result = compile_lock_package(&hash);
    result.validate().unwrap();
    assert_eq!(result.metadata.runtime.trusted_external_verifiers[0].scope, "lock:delegate");
    assert!(result.metadata.locks.iter().any(|lock| {
        lock.name == "delegate"
            && lock
                .proof_plan
                .iter()
                .any(|plan| plan.evidence_tier == cellscript::EvidenceTier::TrustedExternal && plan.on_chain_checked)
    }));
}

#[test]
fn trusted_external_defaults_to_deny_and_requires_an_exact_manifest_binding() {
    let hash = [0x11; 32];
    let raw = source(&hash, false);
    let error =
        compile_with_executable_surface_policy(&raw, options(CellScriptEdition::Edition2027), ExecutableSurfacePolicy::DenyFailClosed)
            .unwrap_err();
    assert_eq!(error.code.as_deref(), Some("E2105"));

    let trusted = source(&hash, true);
    let error = compile_with_executable_surface_policy(
        &trusted,
        options(CellScriptEdition::Edition2027),
        ExecutableSurfacePolicy::DenyFailClosed,
    )
    .unwrap_err();
    assert_eq!(error.code.as_deref(), Some("E2113"));

    let error = compile_package(&hash, &[0x22; 32]).unwrap_err();
    assert_eq!(error.code.as_deref(), Some("E2113"));

    let mut wrong_adapter = declaration(&hash);
    wrong_adapter.adapter = "hex4-v1".to_string();
    let error = compile_custom_package(&source(&hash, true), vec![wrong_adapter]).unwrap_err();
    assert_eq!(error.code.as_deref(), Some("E2113"));
    assert!(error.to_string().contains("no exact Cell.toml binding"));

    let dynamic_hash = source(&hash, true).replace("action verify() -> u64 {", "action verify(witness verifier_hash: Hash) -> u64 {");
    let dynamic_hash = dynamic_hash.replace(&format!("Hash::from_bytes(b\"{}\")", hash_literal(&hash)), "verifier_hash");
    let error = compile_with_executable_surface_policy(
        &dynamic_hash,
        options(CellScriptEdition::Edition2027),
        ExecutableSurfacePolicy::DenyFailClosed,
    )
    .unwrap_err();
    assert!(error.to_string().contains("code_hash must be a compile-time Hash literal"));
}

#[test]
fn trusted_external_declarations_are_closed_used_and_canonical() {
    let hash = [0xab; 32];
    let plain = "module plain\naction verify() -> u64 { return 0 }\n";
    let error = compile_custom_package(plain, vec![declaration(&hash)]).unwrap_err();
    assert_eq!(error.code.as_deref(), Some("E2113"));
    assert!(error.to_string().contains("unused"));

    let mut noncanonical = declaration(&hash);
    noncanonical.code_hash.make_ascii_uppercase();
    let error = compile_custom_package(&source(&hash, true), vec![noncanonical]).unwrap_err();
    assert_eq!(error.code.as_deref(), Some("E2113"));
    assert!(error.to_string().contains("canonical lowercase"));

    let duplicate = declaration(&hash);
    let error = compile_custom_package(&source(&hash, true), vec![duplicate.clone(), duplicate]).unwrap_err();
    assert_eq!(error.code.as_deref(), Some("E2113"));
    assert!(error.to_string().contains("duplicate"));

    let mixed = format!(
        "{}\n",
        source(&hash, true).replace("    require false", "    ckb::exec_cell_dep_u8_args(0, 0, 0, 0, 0, 0)\n    require false")
    );
    let error = compile_custom_package(&mixed, vec![declaration(&hash)]).unwrap_err();
    assert_eq!(error.code.as_deref(), Some("E2113"));
    assert!(error.to_string().contains("mixes trusted and undeclared"));

    let unknown_field = r#"
schema = "cellscript-trusted-external-verifier-v1"
name = "closed-record"
scope = "action:verify"
operation = "exec"
adapter = "u8-args-v1"
code_hash = "abababababababababababababababababababababababababababababababab"
hash_type = "data"
source_identity = "fixture"
applicability = "test"
trust_basis = "hash"
guarantees = ["rejects malformed input"]
evidence_tier = "checked-runtime"
"#;
    let error = toml::from_str::<cellscript::package::CkbTrustedExternalVerifierConfig>(unknown_field).unwrap_err();
    assert!(error.to_string().contains("unknown field `evidence_tier`"));
}

#[test]
fn independent_checker_rejects_hash_removal_and_tier_mutations() {
    let hash = cellscript_artifact_checker::ckb_blake2b256(ALWAYS_SUCCESS.as_ref());
    let result = compile_package(&hash, &hash).unwrap();
    let artifact = result.artifact_bytes;
    let metadata = serde_json::to_value(result.metadata).unwrap();
    let record = result.verified_lowering_record.unwrap();
    let source_map = result.source_artifact_map.unwrap();

    for mutation in ["hash", "adapter", "remove", "tier"] {
        let mut changed_record = record.clone();
        let mut changed_map = source_map.clone();
        let mut changed_metadata = metadata.clone();
        match mutation {
            "hash" => changed_record.typed_semantics.trusted_external_verifiers[0].code_hash = "22".repeat(32),
            "adapter" => changed_record.typed_semantics.trusted_external_verifiers[0].adapter = "hex4-v1".to_string(),
            "remove" => changed_record.typed_semantics.trusted_external_verifiers.clear(),
            "tier" => changed_record.typed_semantics.trusted_external_verifiers[0].evidence_tier = "checked-runtime".to_string(),
            _ => unreachable!(),
        }
        rebind(&mut changed_record, &mut changed_map, &mut changed_metadata);
        let error =
            check_bundle_values(&artifact, &changed_metadata, &changed_record, &changed_map, &CheckerBudgets::default()).unwrap_err();
        assert_eq!(error.code, CheckerRejectionCode::V2419TypedSemanticsInvalid, "{mutation}: {error}");
    }
}
