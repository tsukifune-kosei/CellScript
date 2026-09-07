//! Executable evidence for the bounded typed CKB transaction-view surface.

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

use ckb_script_runner::{build_simple_fixture, execute_cellscript_script, FixtureCell, FixtureHeaderContext};

const SOURCE: &str = r#"
module runtime_views::header

resource Token has store { amount: u64 }

action inspect(witness expected_data_hash: Hash) -> u64 {
    let input = ckb::input<Token>(0)
    let dep = ckb::cell_dep(0)
    let header = ckb::header_dep(0)
    require input.since == 0
    require input.occupied_capacity <= input.capacity
    require input.unoccupied_capacity + input.occupied_capacity == input.capacity
    require dep.data_hash == expected_data_hash
    require header.epoch_number == 42
    require header.epoch_start_block_number == 97
    require header.epoch_length == 10
    return 0
}
"#;

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
    .unwrap_or_else(|error| panic!("typed runtime-view source must compile: {error}\n{source}"))
}

fn witness(result: &cellscript::CompileResult, expected_data_hash: [u8; 32]) -> Bytes {
    let payload = result.metadata.actions[0]
        .entry_witness_args(&[EntryWitnessArg::Hash(expected_data_hash)])
        .expect("encode expected CellDep data hash");
    packed::WitnessArgs::new_builder().input_type(Some(Bytes::from(payload)).pack()).build().as_bytes()
}

fn fixture(dep_data: Bytes, witness: Bytes) -> ckb_script_runner::CkbVmFixture {
    let mut fixture = build_simple_fixture(Bytes::default(), 1, 1);
    fixture.current_type_script_input_indices = vec![0];
    fixture.cell_deps.push(FixtureCell { capacity: 100_000_000_000, type_script: None, data: dep_data });
    fixture.witnesses = vec![witness];
    fixture.header_dao_fields = vec![[0; 32]];
    fixture.header_contexts = vec![FixtureHeaderContext { number: 100, epoch_number: 42, epoch_index: 3, epoch_length: 10 }];
    fixture
}

#[test]
fn typed_cell_input_and_header_views_execute_and_fail_closed() {
    let result = compile(SOURCE);
    let dep_data = Bytes::from_static(b"cellscript-0.30-runtime-view");
    let expected_hash = blake2b_256(&dep_data);

    let valid = fixture(dep_data.clone(), witness(&result, expected_hash));
    let execution = execute_cellscript_script(strip_vm_abi_trailer(&result.artifact_bytes), &valid);
    assert_eq!(execution.exit_code, 0, "all typed runtime-view fields must match: {:?}", execution.captured_debug);

    let mut wrong_hash = expected_hash;
    wrong_hash[0] ^= 0xff;
    let invalid = fixture(dep_data.clone(), witness(&result, wrong_hash));
    let execution = execute_cellscript_script(strip_vm_abi_trailer(&result.artifact_bytes), &invalid);
    assert_ne!(execution.exit_code, 0, "a substituted CellDep data hash must reject");

    let missing_header_result = compile(&SOURCE.replace("ckb::header_dep(0)", "ckb::header_dep(1)"));
    let missing_header = fixture(dep_data, witness(&missing_header_result, expected_hash));
    let execution = execute_cellscript_script(strip_vm_abi_trailer(&missing_header_result.artifact_bytes), &missing_header);
    assert_eq!(execution.exit_code, 45, "a one-past-last HeaderDep must use the stable header-dep-missing error");
}
