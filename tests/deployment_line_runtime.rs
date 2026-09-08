//! Real CKB-VM evidence for active deployment-line handles.

use cellscript::{
    assumptions::validate_transaction_against_metadata, compile_with_executable_surface_policy, strip_vm_abi_trailer,
    CellScriptEdition, CompileOptions, EntryWitnessArg, ExecutableSurfacePolicy,
};
use ckb_testtool::{
    ckb_hash::blake2b_256,
    ckb_types::{bytes::Bytes, core::ScriptHashType, packed, prelude::*},
};

#[path = "support/ckb_script_runner.rs"]
#[allow(dead_code)]
mod ckb_script_runner;

use ckb_script_runner::{
    build_simple_fixture, deterministic_always_success_lock_hash, execute_cellscript_script, CkbVmFixture, FixtureCell,
};

const LINE_BYTES: usize = 386;
const LINE_ADMISSION_TYPE_HASH_OFFSET: usize = 152;
const EXACT_OFFSET: usize = 184;
const EXACT_SCRIPT_HASH_OFFSET: usize = 42;
const EXACT_ARTIFACT_HASH_OFFSET: usize = 106;
const CODE_DATA: &[u8] = b"cellscript-0.30-deployment-line-code";

fn byte_string(bytes: &[u8]) -> String {
    let escaped = bytes.iter().map(|byte| format!("\\x{byte:02x}")).collect::<String>();
    format!("b\"{escaped}\"")
}

fn typed_script(marker: u8) -> packed::Script {
    packed::Script::new_builder()
        .code_hash(packed::Byte32::from_slice(&[marker; 32]).unwrap())
        .hash_type(ScriptHashType::Type)
        .args(Bytes::from(vec![marker.wrapping_add(1); 32]).pack())
        .build()
}

fn line_handle(class: u8, role: u8, script_hash: [u8; 32], admission_type_hash: [u8; 32], artifact_hash: [u8; 32]) -> Vec<u8> {
    let mut handle = vec![0u8; LINE_BYTES];
    handle[..8].copy_from_slice(b"CSLINv1\0");
    handle[8] = class;
    handle[9] = role;
    handle[10] = 0;
    handle[16..24].copy_from_slice(&7u64.to_le_bytes());
    for (offset, marker) in [(24, 0x21), (56, 0x31), (88, 0x41), (120, 0x51)] {
        handle[offset..offset + 32].fill(marker);
    }
    handle[LINE_ADMISSION_TYPE_HASH_OFFSET..LINE_ADMISSION_TYPE_HASH_OFFSET + 32].copy_from_slice(&admission_type_hash);

    let exact = &mut handle[EXACT_OFFSET..];
    exact[..8].copy_from_slice(b"CSHDLv1\0");
    exact[8] = class;
    exact[9] = role;
    for (offset, marker) in [(10, 0x61), (74, 0x71), (138, 0x81), (170, 0x91)] {
        exact[offset..offset + 32].fill(marker);
    }
    exact[EXACT_SCRIPT_HASH_OFFSET..EXACT_SCRIPT_HASH_OFFSET + 32].copy_from_slice(&script_hash);
    exact[EXACT_ARTIFACT_HASH_OFFSET..EXACT_ARTIFACT_HASH_OFFSET + 32].copy_from_slice(&artifact_hash);
    handle
}

fn source(role: &str, handle_hash: [u8; 32]) -> String {
    let call = match role {
        "lock" => "ckb::require_cell_lock_deployment_line_handle(code, admission, code, line, HANDLE_HASH)",
        "type" => "ckb::require_cell_type_deployment_line_handle(code, admission, code, line, HANDLE_HASH)",
        "spawned-verifier" => "ckb::require_cell_dep_deployment_line_verifier_handle(admission, code, line, HANDLE_HASH)",
        _ => unreachable!(),
    };
    format!(
        r#"
module deployment_line::runtime

resource Token has store {{ amount: u64 }}

action verify(witness line: DeploymentLineHandle) -> u64 {{
    let admission = ckb::cell_dep(0)
    let code = ckb::cell_dep(1)
    {call}
    return 0
}}
"#
    )
    .replace("HANDLE_HASH", &format!("Hash::from_bytes({})", byte_string(&handle_hash)))
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
    .unwrap_or_else(|error| panic!("deployment line source must compile: {error}\n{source}"))
}

fn fixture(
    result: &cellscript::CompileResult,
    handle: Vec<u8>,
    admission_type: packed::Script,
    code_type: packed::Script,
    admission_data: Bytes,
    code_data: Bytes,
) -> CkbVmFixture {
    let payload =
        result.metadata.actions[0].entry_witness_args(&[EntryWitnessArg::Bytes(handle)]).expect("encode fixed deployment line handle");
    let witness = packed::WitnessArgs::new_builder().input_type(Some(Bytes::from(payload)).pack()).build().as_bytes();
    let mut fixture = build_simple_fixture(Bytes::default(), 1, 1);
    fixture.current_type_script_input_indices = vec![0];
    fixture.cell_deps = vec![
        FixtureCell { capacity: 100_000_000_000, type_script: Some(admission_type), data: admission_data },
        FixtureCell { capacity: 100_000_000_000, type_script: Some(code_type), data: code_data },
    ];
    fixture.witnesses = vec![witness];
    fixture
}

fn admission_data(handle: &[u8]) -> Bytes {
    let mut data = Vec::from(b"CSREGv1".as_slice());
    data.extend_from_slice(&blake2b_256(handle));
    Bytes::from(data)
}

#[test]
fn deployment_line_verifier_executes_and_rejects_stale_yanked_and_substituted_cells() {
    let admission_type = typed_script(0x31);
    let code_type = typed_script(0x41);
    let code_data = Bytes::from_static(CODE_DATA);
    let handle =
        line_handle(1, 2, code_type.calc_script_hash().unpack(), admission_type.calc_script_hash().unpack(), blake2b_256(&code_data));
    let result = compile(&source("spawned-verifier", blake2b_256(&handle)));
    let elf = strip_vm_abi_trailer(&result.artifact_bytes);
    let valid =
        fixture(&result, handle.clone(), admission_type.clone(), code_type.clone(), admission_data(&handle), code_data.clone());
    assert_eq!(execute_cellscript_script(elf, &valid).exit_code, 0);

    let stale = fixture(
        &result,
        handle.clone(),
        admission_type.clone(),
        code_type.clone(),
        Bytes::from_static(b"CSREGv1stale-state-commitment"),
        code_data.clone(),
    );
    assert_eq!(execute_cellscript_script(elf, &stale).exit_code, 71);

    let mut yanked_handle = handle.clone();
    yanked_handle[10] = 1;
    let yanked = fixture(
        &result,
        yanked_handle.clone(),
        admission_type.clone(),
        code_type.clone(),
        admission_data(&yanked_handle),
        code_data.clone(),
    );
    assert_eq!(execute_cellscript_script(elf, &yanked).exit_code, 71);

    let wrong_admission =
        fixture(&result, handle.clone(), typed_script(0x32), code_type.clone(), admission_data(&handle), code_data.clone());
    assert_eq!(execute_cellscript_script(elf, &wrong_admission).exit_code, 71);

    let wrong_code = fixture(
        &result,
        handle.clone(),
        admission_type,
        code_type,
        admission_data(&handle),
        Bytes::from_static(b"substituted-line-code"),
    );
    assert_eq!(execute_cellscript_script(elf, &wrong_code).exit_code, 71);
}

#[test]
fn deployment_line_script_roles_bind_complete_selected_script_hashes() {
    let admission_type = typed_script(0x51);
    let code_type = typed_script(0x61);
    let code_data = Bytes::from_static(CODE_DATA);
    for (role, role_tag, script_hash) in
        [("lock", 0, deterministic_always_success_lock_hash()), ("type", 1, code_type.calc_script_hash().unpack())]
    {
        let handle = line_handle(0, role_tag, script_hash, admission_type.calc_script_hash().unpack(), blake2b_256(&code_data));
        let result = compile(&source(role, blake2b_256(&handle)));
        let elf = strip_vm_abi_trailer(&result.artifact_bytes);
        let valid =
            fixture(&result, handle.clone(), admission_type.clone(), code_type.clone(), admission_data(&handle), code_data.clone());
        assert_eq!(execute_cellscript_script(elf, &valid).exit_code, 0, "{role} line handle must match");

        if role == "type" {
            let substituted = fixture(
                &result,
                handle.clone(),
                admission_type.clone(),
                typed_script(0x62),
                admission_data(&handle),
                code_data.clone(),
            );
            assert_eq!(execute_cellscript_script(elf, &substituted).exit_code, 71);
        }
    }
}

#[test]
fn deployment_line_surface_is_fixed_and_requires_a_static_full_handle_hash() {
    let admission_type = typed_script(0x71);
    let code_type = typed_script(0x72);
    let handle =
        line_handle(1, 2, code_type.calc_script_hash().unpack(), admission_type.calc_script_hash().unpack(), blake2b_256(CODE_DATA));
    let source = source("spawned-verifier", blake2b_256(&handle));
    let result = compile(&source);
    let param = &result.metadata.actions[0].params[0];
    assert_eq!(param.ty, "DeploymentLineHandle");
    assert_eq!(param.fixed_byte_len, Some(LINE_BYTES));
    assert!(param.fixed_byte_pointer_abi && param.fixed_byte_length_abi);
    assert!(result.metadata.runtime.ckb_runtime_features.contains(&"ckb-deployment-line-handle-v1".to_string()));
    let plan = result.metadata.actions[0]
        .proof_plan
        .iter()
        .find(|plan| plan.category == "deployment-line-handle")
        .expect("deployment line ProofPlan");
    assert!(plan.on_chain_checked);
    assert!(plan.coverage.contains(&"status:active-only".to_string()));

    let dynamic = source
        .replace("witness line: DeploymentLineHandle", "witness line: DeploymentLineHandle, witness dynamic_hash: Hash")
        .replace(&format!("Hash::from_bytes({})", byte_string(&blake2b_256(&handle))), "dynamic_hash");
    let error = compile_with_executable_surface_policy(
        &dynamic,
        CompileOptions {
            edition: CellScriptEdition::Edition2027,
            target: Some("riscv64-elf".to_string()),
            target_profile: Some("ckb".to_string()),
            ..Default::default()
        },
        ExecutableSurfacePolicy::DenyFailClosed,
    )
    .expect_err("dynamic deployment line commitments must be rejected");
    assert!(error.to_string().contains("handle_hash must be a compile-time Hash literal"));
}

#[test]
fn transaction_validation_binds_line_handle_witness_and_both_direct_cell_dep_positions() {
    let admission_type = typed_script(0x81);
    let code_type = typed_script(0x82);
    let code_data = Bytes::from_static(CODE_DATA);
    let handle =
        line_handle(1, 2, code_type.calc_script_hash().unpack(), admission_type.calc_script_hash().unpack(), blake2b_256(&code_data));
    let result = compile(&source("spawned-verifier", blake2b_256(&handle)));
    let assumption = result
        .metadata
        .runtime
        .builder_assumptions
        .iter()
        .find(|assumption| assumption.kind == "deployment_line_handle")
        .expect("deployment line builder assumption");
    assert_eq!(assumption.required_cell_deps, ["cell_dep:*"]);
    assert_eq!(assumption.required_witness_fields, ["DeploymentLineHandle"]);

    let payload = result.metadata.actions[0]
        .entry_witness_args(&[EntryWitnessArg::Bytes(handle.clone())])
        .expect("encode deployment line entry payload");
    let script_json = |script: &packed::Script| {
        serde_json::json!({
            "code_hash": format!("0x{}", hex::encode(script.code_hash().as_slice())),
            "hash_type": "type",
            "args": format!("0x{}", hex::encode(script.args().raw_data())),
        })
    };
    let admission_data = admission_data(&handle);
    let evidence = serde_json::json!({
        "assumption_id": assumption.assumption_id,
        "kind": assumption.kind,
        "origin": assumption.origin,
        "feature": assumption.feature,
        "proof_plan_status": assumption.proof_plan_status,
        "evidence": {
            "handle": format!("0x{}", hex::encode(&handle)),
            "source": { "location": "cell_dep", "index": 1 },
            "admission": { "index": 0 },
            "code": { "index": 1 },
            "witness": { "index": 0, "field": "input_type" },
        },
    });
    let mut tx = serde_json::json!({
        "inputs": [{}],
        "outputs": [{}],
        "cell_deps": [
            {
                "dep_type": "code",
                "type": script_json(&admission_type),
                "data": format!("0x{}", hex::encode(&admission_data)),
            },
            {
                "dep_type": "code",
                "type": script_json(&code_type),
                "data": format!("0x{}", hex::encode(&code_data)),
                "data_hash": format!("0x{}", hex::encode(blake2b_256(&code_data))),
            }
        ],
        "witnesses": [{ "input_type": format!("0x{}", hex::encode(&payload)) }],
        "builder_assumption_evidence": { assumption.assumption_id.clone(): evidence },
    });
    let report = validate_transaction_against_metadata(&result.metadata, &tx);
    assert_eq!(report.status, "ok", "valid deployment line evidence must pass: {:?}", report.violations);

    let valid = tx.clone();
    tx["builder_assumption_evidence"][&assumption.assumption_id]["evidence"]["admission"]["index"] = serde_json::json!(1);
    assert_eq!(validate_transaction_against_metadata(&result.metadata, &tx).status, "failed");

    tx = valid.clone();
    tx["cell_deps"][0]["data"] = serde_json::json!("0x00");
    assert_eq!(validate_transaction_against_metadata(&result.metadata, &tx).status, "failed");

    tx = valid.clone();
    tx["cell_deps"][1]["data_hash"] = serde_json::json!(format!("0x{}", "00".repeat(32)));
    assert_eq!(validate_transaction_against_metadata(&result.metadata, &tx).status, "failed");

    tx = valid;
    let mut wrong_position = payload;
    wrong_position[8] ^= 0xff;
    tx["witnesses"][0]["input_type"] = serde_json::json!(format!("0x{}", hex::encode(wrong_position)));
    assert_eq!(validate_transaction_against_metadata(&result.metadata, &tx).status, "failed");
}
