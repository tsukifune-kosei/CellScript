//! CKB-VM and metadata evidence for fixed exact Script handles.

use cellscript::{
    compile_with_executable_surface_policy, strip_vm_abi_trailer, CellScriptEdition, CompileOptions, EntryWitnessArg,
    ExecutableSurfacePolicy,
};
use ckb_testtool::{
    ckb_hash::blake2b_256,
    ckb_types::{bytes::Bytes, packed, prelude::*},
};

#[path = "support/ckb_script_runner.rs"]
#[allow(dead_code)]
mod ckb_script_runner;

use ckb_script_runner::{build_simple_fixture, execute_cellscript_script, CkbVmFixture, FixtureCell};

const HANDLE_BYTES: usize = 202;
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
