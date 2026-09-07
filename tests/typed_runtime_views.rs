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

fn preserve_epoch_since(value: AbsoluteEpochSince) -> AbsoluteEpochSince {
    return value
}

action inspect(witness expected_data_hash: Hash) -> u64 {
    let input = ckb::input<Token>(0)
    let dep = ckb::cell_dep(0)
    let header = ckb::header_dep(0)
    let earlier = preserve_epoch_since(ckb::since_absolute_epoch(42, 3, 10))
    let later = ckb::since_absolute_epoch(43, 0, 10)
    let half = ckb::since_absolute_epoch(42, 1, 2)
    let two_fifths = ckb::since_absolute_epoch(42, 2, 5)
    let equivalent_half = ckb::since_absolute_epoch(42, 2, 4)
    let relative = ckb::since_relative_epoch(2, 1, 4)
    let absolute_block = ckb::since_absolute_block(123)
    let later_absolute_block = ckb::since_absolute_block(124)
    let relative_block = ckb::since_relative_block(7)
    let absolute_timestamp = ckb::since_absolute_timestamp(1700000000)
    let later_absolute_timestamp = ckb::since_absolute_timestamp(1700000001)
    let relative_timestamp = ckb::since_relative_timestamp(3600)
    let disabled = ckb::since_decode(input.since)
    let five_epochs = ckb::epoch_duration(5)
    let seven_epochs = ckb::epoch_duration(7)
    let epoch_after = ckb::epoch_add(header.epoch_number, five_epochs)
    let epoch_before = ckb::epoch_sub(header.epoch_number, five_epochs)
    let decoded_epoch = ckb::since_from_raw_checked(2305854004380303402)
    let decoded_zero_fraction = ckb::since_from_raw_checked(2305843009213693994)
    let decoded_relative_timestamp = ckb::since_from_raw_checked(13835058055282167312)
    require ckb::since_to_raw(earlier) == 2305854004380303402
    require earlier < later
    require earlier <= later
    require later > earlier
    require later >= earlier
    require half > two_fifths
    require half == equivalent_half
    require half != two_fifths
    require ckb::since_to_raw(relative) == 11529219444131758082
    require ckb::since_to_raw(absolute_block) == 123
    require ckb::since_to_raw(relative_block) == 9223372036854775815
    require absolute_block < later_absolute_block
    require ckb::since_to_raw(absolute_timestamp) == 4611686020127387904
    require ckb::since_to_raw(relative_timestamp) == 13835058055282167312
    require absolute_timestamp < later_absolute_timestamp
    require ckb::since_is_disabled(disabled)
    require !ckb::since_is_relative(disabled)
    require ckb::since_metric(disabled) == 0
    require ckb::since_value(disabled) == 0
    require ckb::since_metric(decoded_epoch) == 1
    require ckb::since_value(decoded_epoch) == 10995166609450
    require ckb::since_as_absolute_epoch(decoded_epoch) == earlier
    require ckb::since_as_absolute_epoch(decoded_zero_fraction) == ckb::since_absolute_epoch(42, 0, 1)
    require ckb::since_is_relative(decoded_relative_timestamp)
    require ckb::since_metric(decoded_relative_timestamp) == 2
    require ckb::since_value(decoded_relative_timestamp) == 3600
    require ckb::since_as_relative_timestamp(decoded_relative_timestamp) == relative_timestamp
    require five_epochs < seven_epochs
    require ckb::epoch_duration_to_u64(five_epochs) == 5
    require ckb::epoch_number_to_u64(epoch_after) == 47
    require ckb::epoch_number_to_u64(epoch_before) == 37
    require ckb::since_to_raw(input.since) == 0
    require input.occupied_capacity <= input.capacity
    require input.unoccupied_capacity + input.occupied_capacity == input.capacity
    require dep.data_hash == expected_data_hash
    require ckb::epoch_number_to_u64(header.epoch_number) == 42
    require ckb::block_number_to_u64(header.epoch_start_block_number) == 97
    require ckb::epoch_length_to_u64(header.epoch_length) == 10
    require ckb::block_number_to_u64(header.block_number) == 100
    require ckb::timestamp_millis_to_u64(header.timestamp) == 1700000000123
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
    fixture.header_contexts =
        vec![FixtureHeaderContext { number: 100, timestamp: 1_700_000_000_123, epoch_number: 42, epoch_index: 3, epoch_length: 10 }];
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
    assert!(result.metadata.runtime.ckb_runtime_features.contains(&"ckb-epoch-checked-arithmetic".to_string()));
    assert!(result.metadata.runtime.ckb_runtime_features.contains(&"ckb-header-full-decode".to_string()));
    assert!(result.metadata.runtime.ckb_runtime_features.contains(&"ckb-header-block-number".to_string()));
    assert!(result.metadata.runtime.ckb_runtime_features.contains(&"ckb-header-timestamp-millis".to_string()));
    assert!(result.metadata.runtime.ckb_runtime_accesses.iter().any(|access| {
        access.syscall == "LOAD_HEADER" && access.source == "HeaderDep" && access.operation == "header-dep-timestamp-millis"
    }));

    let mut wrong_hash = expected_hash;
    wrong_hash[0] ^= 0xff;
    let invalid = fixture(dep_data.clone(), witness(&result, wrong_hash));
    let execution = execute_cellscript_script(strip_vm_abi_trailer(&result.artifact_bytes), &invalid);
    assert_ne!(execution.exit_code, 0, "a substituted CellDep data hash must reject");

    let missing_header_result = compile(&SOURCE.replace("ckb::header_dep(0)", "ckb::header_dep(1)"));
    let missing_header = fixture(dep_data, witness(&missing_header_result, expected_hash));
    let execution = execute_cellscript_script(strip_vm_abi_trailer(&missing_header_result.artifact_bytes), &missing_header);
    assert_eq!(execution.exit_code, 45, "a one-past-last HeaderDep must use the stable header-dep-missing error");

    let malformed_since_result =
        compile(&SOURCE.replace("ckb::since_absolute_epoch(42, 3, 10)", "ckb::since_absolute_epoch(42, 0, 0)"));
    let malformed_since =
        fixture(Bytes::from_static(b"cellscript-0.30-runtime-view"), witness(&malformed_since_result, expected_hash));
    let execution = execute_cellscript_script(strip_vm_abi_trailer(&malformed_since_result.artifact_bytes), &malformed_since);
    assert_eq!(execution.exit_code, 37, "a zero-length epoch fraction must use ckb-since-malformed");

    for source in [
        SOURCE.replace("ckb::since_absolute_block(123)", "ckb::since_absolute_block(72057594037927936)"),
        SOURCE.replace("ckb::since_absolute_timestamp(1700000000)", "ckb::since_absolute_timestamp(18446744073709552)"),
        SOURCE.replace("ckb::since_from_raw_checked(2305854004380303402)", "ckb::since_from_raw_checked(72057594037927936)"),
        SOURCE.replace("ckb::since_from_raw_checked(2305854004380303402)", "ckb::since_from_raw_checked(6917529027641081856)"),
        SOURCE.replace("ckb::since_from_raw_checked(2305854004380303402)", "ckb::since_from_raw_checked(2305844108742098986)"),
        SOURCE.replace("ckb::since_from_raw_checked(2305854004380303402)", "ckb::since_from_raw_checked(4630132762501097456)"),
        SOURCE.replace(
            "require ckb::since_as_absolute_epoch(decoded_epoch) == earlier",
            "require ckb::since_to_raw(ckb::since_as_relative_epoch(decoded_epoch)) >= 0",
        ),
    ] {
        let result = compile(&source);
        let invalid = fixture(Bytes::from_static(b"cellscript-0.30-runtime-view"), witness(&result, expected_hash));
        let execution = execute_cellscript_script(strip_vm_abi_trailer(&result.artifact_bytes), &invalid);
        assert_eq!(execution.exit_code, 37, "malformed or mismatched typed Since values must fail closed");
    }

    for source in [
        SOURCE.replace("ckb::epoch_duration(5)", "ckb::epoch_duration(16777216)"),
        SOURCE.replace(
            "let epoch_after = ckb::epoch_add(header.epoch_number, five_epochs)",
            "let epoch_after = ckb::epoch_add(header.epoch_number, ckb::epoch_duration(16777215))",
        ),
        SOURCE.replace(
            "let epoch_before = ckb::epoch_sub(header.epoch_number, five_epochs)",
            "let epoch_before = ckb::epoch_sub(header.epoch_number, ckb::epoch_duration(43))",
        ),
    ] {
        let result = compile(&source);
        let invalid = fixture(Bytes::from_static(b"cellscript-0.30-runtime-view"), witness(&result, expected_hash));
        let execution = execute_cellscript_script(strip_vm_abi_trailer(&result.artifact_bytes), &invalid);
        assert_eq!(execution.exit_code, 20, "invalid EpochDuration arithmetic must use numeric-or-discriminant-invalid");
    }
}
