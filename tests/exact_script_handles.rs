//! CKB-VM and metadata evidence for fixed exact Script handles.

use cellscript::assumptions::validate_transaction_against_metadata;
use cellscript::{
    compile_with_executable_surface_policy, strip_vm_abi_trailer, CellScriptEdition, CompileOptions, EntryWitnessArg,
    ExecutableSurfacePolicy,
};
use ckb_testtool::{
    ckb_hash::blake2b_256,
    ckb_types::{bytes::Bytes, packed, prelude::*},
};
use std::process::Command;

#[path = "support/ckb_script_runner.rs"]
#[allow(dead_code)]
mod ckb_script_runner;

use ckb_script_runner::{build_simple_fixture, execute_cellscript_script, CkbVmFixture, FixtureCell};

const HANDLE_BYTES: usize = 202;
const SCRIPT_HASH_OFFSET: usize = 42;
const ARTIFACT_HASH_OFFSET: usize = 106;
const DEP_DATA: &[u8] = b"cellscript-0.30-exact-verifier";

fn byte_string(bytes: &[u8]) -> String {
    let escaped = bytes.iter().map(|byte| format!("\\x{byte:02x}")).collect::<String>();
    format!("b\"{escaped}\"")
}

fn verifier_handle(dep_hash: [u8; 32]) -> Vec<u8> {
    let mut handle = vec![0u8; HANDLE_BYTES];
    handle[..8].copy_from_slice(b"CSHDLv1\0");
    handle[8] = 1;
    handle[9] = 2;
    for (offset, value) in [(10, 0x11), (42, 0x22), (74, 0x33), (138, 0x44), (170, 0x55)] {
        handle[offset..offset + 32].fill(value);
    }
    handle[ARTIFACT_HASH_OFFSET..ARTIFACT_HASH_OFFSET + 32].copy_from_slice(&dep_hash);
    handle
}

fn script_handle(role: u8, script_hash: [u8; 32], marker: u8) -> Vec<u8> {
    let mut handle = vec![0u8; HANDLE_BYTES];
    handle[..8].copy_from_slice(b"CSHDLv1\0");
    handle[8] = 0;
    handle[9] = role;
    for offset in [10, 74, 106, 138, 170] {
        handle[offset..offset + 32].fill(marker);
    }
    handle[SCRIPT_HASH_OFFSET..SCRIPT_HASH_OFFSET + 32].copy_from_slice(&script_hash);
    handle
}

fn verifier_source(expected_handle_hash: [u8; 32]) -> String {
    format!(
        r#"
module exact_handles::verifier

resource Token has store {{ amount: u64 }}

action verify(witness verifier_handle: ExactScriptHandle) -> u64 {{
    let dep = ckb::cell_dep(0)
    ckb::require_cell_dep_exact_verifier_handle(
        dep,
        verifier_handle,
        Hash::from_bytes({})
    )
    return 0
}}
"#,
        byte_string(&expected_handle_hash)
    )
}

fn compile(source: &str) -> cellscript::CompileResult {
    compile_with_executable_surface_policy(
        source,
        CompileOptions {
            edition: CellScriptEdition::Edition2027,
            target: Some("riscv64-elf".to_string()),
            target_profile: Some("ckb".to_string()),
            ..Default::default()
        },
        ExecutableSurfacePolicy::DenyFailClosed,
    )
    .unwrap_or_else(|error| panic!("exact Script handle source must compile: {error}\n{source}"))
}

fn fixture(result: &cellscript::CompileResult, handle: Vec<u8>, dep_data: Bytes) -> CkbVmFixture {
    let payload =
        result.metadata.actions[0].entry_witness_args(&[EntryWitnessArg::Bytes(handle)]).expect("encode fixed exact verifier handle");
    let witness = packed::WitnessArgs::new_builder().input_type(Some(Bytes::from(payload)).pack()).build().as_bytes();
    let mut fixture = build_simple_fixture(Bytes::default(), 1, 1);
    fixture.current_type_script_input_indices = vec![0];
    fixture.cell_deps.push(FixtureCell { capacity: 100_000_000_000, type_script: None, data: dep_data });
    fixture.witnesses = vec![witness];
    fixture
}

#[test]
fn exact_verifier_handle_executes_and_rejects_every_substitution_class() {
    let dep_data = Bytes::from_static(DEP_DATA);
    let handle = verifier_handle(blake2b_256(&dep_data));
    let result = compile(&verifier_source(blake2b_256(&handle)));
    let elf = strip_vm_abi_trailer(&result.artifact_bytes);

    let execution = execute_cellscript_script(elf, &fixture(&result, handle.clone(), dep_data.clone()));
    assert_eq!(execution.exit_code, 0, "the exact verifier artifact must match: {:?}", execution.captured_debug);

    for offset in [0, 8, 9, 10, 42, 74, 106, 138, 170, 201] {
        let mut substituted = handle.clone();
        substituted[offset] ^= 0xff;
        let execution = execute_cellscript_script(elf, &fixture(&result, substituted, dep_data.clone()));
        assert_eq!(execution.exit_code, 70, "substitution at handle byte {offset} must fail closed");
    }

    let execution = execute_cellscript_script(elf, &fixture(&result, handle, Bytes::from_static(b"substituted-verifier-artifact")));
    assert_eq!(execution.exit_code, 70, "a substituted CellDep verifier artifact must fail closed");
}

#[test]
fn exact_handle_surface_binds_abi_metadata_proof_plan_and_static_hashes() {
    let dep_hash = blake2b_256(DEP_DATA);
    let handle = verifier_handle(dep_hash);
    let expected_handle_hash = blake2b_256(&handle);
    let result = compile(&verifier_source(expected_handle_hash));
    let action = &result.metadata.actions[0];
    let param = &action.params[0];
    assert_eq!(param.ty, "ExactScriptHandle");
    assert_eq!(param.fixed_byte_len, Some(HANDLE_BYTES));
    assert!(param.fixed_byte_pointer_abi && param.fixed_byte_length_abi);
    assert!(!param.schema_pointer_abi && !param.cell_bound_abi);
    assert!(result.metadata.runtime.ckb_runtime_features.contains(&"ckb-exact-script-handle-v1".to_string()));
    assert!(result.metadata.runtime.ckb_runtime_accesses.iter().any(|access| {
        access.operation == "exact-handle-verifier-artifact-binding"
            && access.source == "CellDep"
            && access.syscall == "LOAD_CELL_BY_FIELD"
            && access.provenance.range.length.value == Some(32)
    }));
    let plan = action.proof_plan.iter().find(|plan| plan.category == "exact-script-handle").expect("exact-handle ProofPlan");
    assert_eq!(plan.evidence_tier.as_str(), "checked-runtime");
    assert!(plan.on_chain_checked);
    assert!(plan.feature.ends_with(&hex::encode(expected_handle_hash)));
    assert!(plan.coverage.contains(&"receipt-commitment:bound-by-full-handle-hash".to_string()));

    let static_surface = format!(
        r#"
module exact_handles::static_surface
resource Token has store {{ amount: u64 }}
action verify(
    witness lock_handle: ExactScriptHandle,
    witness type_handle: ExactScriptHandle
) -> u64 {{
    let input = ckb::input<Token>(0)
    ckb::require_cell_lock_exact_handle(input, lock_handle, Hash::from_bytes({hash}))
    ckb::require_cell_type_exact_handle(input, type_handle, Hash::from_bytes({hash}))
    return 0
}}
"#,
        hash = byte_string(&expected_handle_hash)
    );
    let static_result = compile(&static_surface);
    assert_eq!(static_result.metadata.actions[0].proof_plan.iter().filter(|plan| plan.category == "exact-script-handle").count(), 2);

    let dynamic_hash = static_surface
        .replace("witness type_handle: ExactScriptHandle", "witness type_handle: ExactScriptHandle, witness dynamic_hash: Hash");
    let dynamic_hash = dynamic_hash.replace(&format!("Hash::from_bytes({})", byte_string(&expected_handle_hash)), "dynamic_hash");
    let error = compile_with_executable_surface_policy(
        &dynamic_hash,
        CompileOptions {
            edition: CellScriptEdition::Edition2027,
            target: Some("riscv64-elf".to_string()),
            target_profile: Some("ckb".to_string()),
            ..Default::default()
        },
        ExecutableSurfacePolicy::DenyFailClosed,
    )
    .expect_err("dynamic exact-handle commitments must be rejected");
    assert!(error.to_string().contains("handle_hash must be a compile-time Hash literal"));

    let untyped_source = static_surface.replace("let input = ckb::input<Token>(0)", "let input = 0");
    let error = compile_with_executable_surface_policy(
        &untyped_source,
        CompileOptions {
            edition: CellScriptEdition::Edition2027,
            target: Some("riscv64-elf".to_string()),
            target_profile: Some("ckb".to_string()),
            ..Default::default()
        },
        ExecutableSurfacePolicy::DenyFailClosed,
    )
    .expect_err("raw source indexes must not impersonate typed views for exact handles");
    assert!(error.to_string().contains("expects (source_view, handle: ExactScriptHandle"));
}

#[test]
fn tx_validate_binds_exact_handle_to_witness_parameter_and_cell_dep_position() {
    let dep_hash = blake2b_256(DEP_DATA);
    let handle = verifier_handle(dep_hash);
    let handle_hash = blake2b_256(&handle);
    let result = compile(&verifier_source(handle_hash));
    let assumption = result
        .metadata
        .runtime
        .builder_assumptions
        .iter()
        .find(|assumption| assumption.kind == "exact_script_handle")
        .expect("exact handle builder assumption");
    assert_eq!(assumption.required_cell_deps, ["cell_dep:*"]);
    assert_eq!(assumption.required_witness_fields, ["ExactScriptHandle"]);

    let entry_payload = result.metadata.actions[0]
        .entry_witness_args(&[EntryWitnessArg::Bytes(handle.clone())])
        .expect("encode exact handle entry payload");
    let evidence = serde_json::json!({
        "assumption_id": assumption.assumption_id,
        "kind": assumption.kind,
        "origin": assumption.origin,
        "feature": assumption.feature,
        "proof_plan_status": assumption.proof_plan_status,
        "evidence": {
            "handle": format!("0x{}", hex::encode(&handle)),
            "source": { "location": "cell_dep", "index": 0 },
            "witness": { "index": 0, "field": "input_type" },
        },
    });
    let mut tx = serde_json::json!({
        "inputs": [{}],
        "outputs": [{}],
        "cell_deps": [{
            "out_point": { "tx_hash": format!("0x{}", "11".repeat(32)), "index": 0 },
            "dep_type": "code",
            "data_hash": format!("0x{}", hex::encode(dep_hash)),
        }],
        "witnesses": [{ "input_type": format!("0x{}", hex::encode(&entry_payload)) }],
        "builder_assumption_evidence": { assumption.assumption_id.clone(): evidence },
    });
    let report = validate_transaction_against_metadata(&result.metadata, &tx);
    assert_eq!(report.status, "ok", "valid exact handle evidence must pass: {:?}", report.violations);

    let root = tempfile::tempdir().unwrap();
    let metadata_path = root.path().join("exact.meta.json");
    let tx_path = root.path().join("exact.tx.json");
    std::fs::write(&metadata_path, serde_json::to_vec_pretty(&result.metadata).unwrap()).unwrap();
    std::fs::write(&tx_path, serde_json::to_vec_pretty(&tx).unwrap()).unwrap();
    let cli = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .args(["tx", "validate", "--against"])
        .arg(&metadata_path)
        .arg("--tx")
        .arg(&tx_path)
        .arg("--json")
        .output()
        .unwrap();
    assert!(cli.status.success(), "{}", String::from_utf8_lossy(&cli.stderr));
    let summary: serde_json::Value = serde_json::from_slice(&cli.stdout).unwrap();
    assert_eq!(summary["status"], "ok");
    assert_eq!(summary["validation"]["checked_assumptions"], serde_json::json!([assumption.assumption_id]));

    let raw_witness =
        packed::WitnessArgs::new_builder().input_type(Some(Bytes::from(entry_payload.clone())).pack()).build().as_bytes();
    tx["witnesses"][0] = serde_json::json!(format!("0x{}", hex::encode(raw_witness)));
    let report = validate_transaction_against_metadata(&result.metadata, &tx);
    assert_eq!(report.status, "ok", "raw canonical WitnessArgs must be decoded: {:?}", report.violations);

    tx["witnesses"][0] = serde_json::json!({ "input_type": format!("0x{}", hex::encode(&entry_payload)) });
    let valid = tx.clone();
    for offset in [0, 8, 9, 10, 42, 74, 106, 138, 170, 201] {
        tx = valid.clone();
        let mut changed = handle.clone();
        changed[offset] ^= 0xff;
        tx["builder_assumption_evidence"][&assumption.assumption_id]["evidence"]["handle"] =
            serde_json::json!(format!("0x{}", hex::encode(changed)));
        let report = validate_transaction_against_metadata(&result.metadata, &tx);
        assert_eq!(report.status, "failed", "handle substitution at byte {offset} must fail tx validate");
    }

    tx = valid.clone();
    tx["cell_deps"][0]["data_hash"] = serde_json::json!(format!("0x{}", "22".repeat(32)));
    assert_eq!(validate_transaction_against_metadata(&result.metadata, &tx).status, "failed");

    tx = valid.clone();
    tx["builder_assumption_evidence"][&assumption.assumption_id]["evidence"]["source"]["index"] = serde_json::json!(1);
    assert_eq!(validate_transaction_against_metadata(&result.metadata, &tx).status, "failed");

    tx = valid.clone();
    tx["builder_assumption_evidence"][&assumption.assumption_id]["evidence"]["witness"]["index"] = serde_json::json!(1);
    assert_eq!(validate_transaction_against_metadata(&result.metadata, &tx).status, "failed");

    tx = valid.clone();
    let mut wrong_parameter = entry_payload;
    wrong_parameter[8] ^= 0xff;
    tx["witnesses"][0]["input_type"] = serde_json::json!(format!("0x{}", hex::encode(wrong_parameter)));
    assert_eq!(validate_transaction_against_metadata(&result.metadata, &tx).status, "failed");
}

#[test]
fn tx_validate_binds_lock_and_type_handles_to_full_script_identity_and_parameter_order() {
    let lock_script = packed::Script::new_builder()
        .code_hash(packed::Byte32::from_slice(&[0x31; 32]).unwrap())
        .hash_type(ckb_testtool::ckb_types::core::ScriptHashType::Data2)
        .args(Bytes::from_static(b"lock-args").pack())
        .build();
    let type_script = packed::Script::new_builder()
        .code_hash(packed::Byte32::from_slice(&[0x41; 32]).unwrap())
        .hash_type(ckb_testtool::ckb_types::core::ScriptHashType::Type)
        .args(Bytes::from_static(b"type-args").pack())
        .build();
    let lock_hash: [u8; 32] = lock_script.calc_script_hash().as_slice().try_into().unwrap();
    let type_hash: [u8; 32] = type_script.calc_script_hash().as_slice().try_into().unwrap();
    let lock_handle = script_handle(0, lock_hash, 0x51);
    let type_handle = script_handle(1, type_hash, 0x61);
    let source = format!(
        r#"
module exact_handles::script_tx_validation
resource Token has store {{ amount: u64 }}
action verify(
    witness lock_handle: ExactScriptHandle,
    witness type_handle: ExactScriptHandle
) -> u64 {{
    let input = ckb::input<Token>(0)
    ckb::require_cell_lock_exact_handle(input, lock_handle, Hash::from_bytes({lock_hash}))
    ckb::require_cell_type_exact_handle(input, type_handle, Hash::from_bytes({type_hash}))
    return 0
}}
"#,
        lock_hash = byte_string(&blake2b_256(&lock_handle)),
        type_hash = byte_string(&blake2b_256(&type_handle)),
    );
    let result = compile(&source);
    let entry_payload = result.metadata.actions[0]
        .entry_witness_args(&[EntryWitnessArg::Bytes(lock_handle.clone()), EntryWitnessArg::Bytes(type_handle.clone())])
        .unwrap();
    let script_json = |code_hash: u8, hash_type: &str, args: &[u8]| {
        serde_json::json!({
            "code_hash": format!("0x{}", hex::encode([code_hash; 32])),
            "hash_type": hash_type,
            "args": format!("0x{}", hex::encode(args)),
        })
    };
    let mut evidence = serde_json::Map::new();
    for assumption in result.metadata.runtime.builder_assumptions.iter().filter(|assumption| assumption.kind == "exact_script_handle")
    {
        let handle = if assumption.feature.starts_with("lock:") { &lock_handle } else { &type_handle };
        evidence.insert(
            assumption.assumption_id.clone(),
            serde_json::json!({
                "assumption_id": assumption.assumption_id,
                "kind": assumption.kind,
                "origin": assumption.origin,
                "feature": assumption.feature,
                "proof_plan_status": assumption.proof_plan_status,
                "evidence": {
                    "handle": format!("0x{}", hex::encode(handle)),
                    "source": { "location": "input", "index": 0 },
                    "witness": { "index": 0, "field": "input_type" },
                },
            }),
        );
    }
    assert_eq!(evidence.len(), 2);
    let mut tx = serde_json::json!({
        "inputs": [{
            "out_point": { "tx_hash": format!("0x{}", "71".repeat(32)), "index": 0 },
            "lock": script_json(0x31, "data2", b"lock-args"),
            "type": script_json(0x41, "type", b"type-args"),
        }],
        "outputs": [],
        "cell_deps": [],
        "witnesses": [{ "input_type": format!("0x{}", hex::encode(&entry_payload)) }],
        "builder_assumption_evidence": evidence,
    });
    let report = validate_transaction_against_metadata(&result.metadata, &tx);
    assert_eq!(report.status, "ok", "full lock/type Script identities must validate: {:?}", report.violations);

    let valid = tx.clone();
    let swapped_payload = result.metadata.actions[0]
        .entry_witness_args(&[EntryWitnessArg::Bytes(type_handle), EntryWitnessArg::Bytes(lock_handle)])
        .unwrap();
    tx["witnesses"][0]["input_type"] = serde_json::json!(format!("0x{}", hex::encode(swapped_payload)));
    assert_eq!(
        validate_transaction_against_metadata(&result.metadata, &tx).status,
        "failed",
        "handle bytes in the wrong compiled parameter positions must fail"
    );

    tx = valid;
    tx["inputs"][0]["lock"]["args"] = serde_json::json!("0x00");
    assert_eq!(
        validate_transaction_against_metadata(&result.metadata, &tx).status,
        "failed",
        "a Script args substitution must fail the complete Script hash binding"
    );
}
