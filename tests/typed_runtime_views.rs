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

const DYNAMIC_INDEX_SOURCE: &str = r#"
module runtime_views::dynamic_index

resource Token has store { amount: u64 }

action inspect(witness source_index: u64, witness expected_data_hash: Hash) -> u64 {
    let input = ckb::input<Token>(source_index)
    let dep = ckb::cell_dep(source_index)
    let witness_args = witness::args(source_index)
    require input.capacity > 0
    require dep.data_hash == expected_data_hash
    require witness_args.size > 0
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

fn dynamic_index_witness(result: &cellscript::CompileResult, source_index: u64, expected_data_hash: [u8; 32]) -> Bytes {
    let payload = result.metadata.actions[0]
        .entry_witness_args(&[EntryWitnessArg::U64(source_index), EntryWitnessArg::Hash(expected_data_hash)])
        .expect("encode dynamic source index and expected CellDep data hash");
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

#[test]
fn dynamic_source_indexes_execute_and_emit_checked_provenance() {
    let result = compile(DYNAMIC_INDEX_SOURCE);
    let dep_data = Bytes::from_static(b"cellscript-0.30-dynamic-index");
    let expected_hash = blake2b_256(&dep_data);

    let valid = fixture(dep_data.clone(), dynamic_index_witness(&result, 0, expected_hash));
    let execution = execute_cellscript_script(strip_vm_abi_trailer(&result.artifact_bytes), &valid);
    assert_eq!(execution.exit_code, 0, "dynamic index zero must select the first Input, CellDep, and Witness");

    let dynamic_accesses = result
        .metadata
        .runtime
        .ckb_runtime_accesses
        .iter()
        .filter(|access| access.provenance.index.kind == "dynamic")
        .collect::<Vec<_>>();
    assert!(!dynamic_accesses.is_empty(), "runtime metadata must preserve dynamic source-index provenance");
    assert!(dynamic_accesses.iter().all(|access| {
        access.provenance.contract == cellscript::CKB_RUNTIME_ACCESS_PROVENANCE_CONTRACT
            && access.provenance.index.binding.as_deref() == Some("source_index")
            && access.provenance.index.max_inclusive == Some(u64::from(u32::MAX))
            && access.index == 0
    }));
    assert!(dynamic_accesses.iter().any(|access| {
        access.operation == "cell-data-hash-field"
            && access.provenance.source.resolved_source == "CellDep"
            && access.provenance.source.origin == "inherited-source-view"
            && access.provenance.range.kind == "fixed-width"
            && access.provenance.range.length.value == Some(32)
    }));
    assert!(result.metadata.runtime.transaction_view_handles.iter().any(|handle| {
        handle.handle_type == "InputView<Token>"
            && handle.provenance.index.kind == "dynamic"
            && handle.provenance.index.binding.as_deref() == Some("source_index")
    }));

    let invalid = fixture(dep_data, dynamic_index_witness(&result, u64::from(u32::MAX) + 1, expected_hash));
    let execution = execute_cellscript_script(strip_vm_abi_trailer(&result.artifact_bytes), &invalid);
    assert_eq!(execution.exit_code, 44, "a dynamic source index outside the packed 32-bit view domain must fail closed");

    let mut tampered = result.metadata.clone();
    let access = tampered
        .runtime
        .ckb_runtime_accesses
        .iter_mut()
        .find(|access| access.provenance.index.kind == "dynamic")
        .expect("dynamic runtime access");
    access.provenance.index.max_inclusive = Some(u64::from(u32::MAX) - 1);
    let error = cellscript::validate_compile_metadata(&tampered, result.artifact_format)
        .expect_err("a narrowed source-view index contract must not validate");
    assert!(error.message.contains("32-bit source-view index"), "unexpected validation error: {error}");
}

fn byte_string_literal(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("\\x{byte:02x}")).collect()
}

fn bounded_witness_fixture(witness: Bytes) -> ckb_script_runner::CkbVmFixture {
    let mut fixture = build_simple_fixture(Bytes::default(), 1, 1);
    fixture.current_type_script_input_indices = vec![0];
    fixture.witnesses = vec![witness];
    fixture
}

fn bounded_read_source(raw: &[u8], lock: &[u8], entry: &[u8], output_type: &[u8]) -> String {
    let entry_u32 = u32::from_le_bytes(entry[501..505].try_into().expect("entry u32 bytes"));
    let output_u64 = u64::from_le_bytes(output_type[777..785].try_into().expect("output u64 bytes"));
    format!(
        r#"module runtime_views::bounded_witness

action inspect() -> u64 {{
    verification
        let witness_args = witness::args(0)
        let raw = witness::bounded_raw(witness_args, 4096)
        let lock = witness::bounded_lock(witness_args, 700)
        let entry = witness::bounded_entry(witness_args, 900)
        let output_type = witness::bounded_output_type(witness_args, 1024)
        require raw.size == {raw_size}
        require lock.size == 700
        require entry.size == 900
        require output_type.size == 1024
        require witness::byte(lock, 0) == {lock_first}
        require witness::byte(lock, 699) == {lock_last}
        require witness::u32_le(entry, 501) == {entry_u32}
        require witness::u64_le(output_type, 777) == {output_u64}
        require witness::blake2b(raw) == Hash::from_bytes(b"{raw_hash}")
        require witness::blake2b(lock) == Hash::from_bytes(b"{lock_hash}")
        require witness::blake2b(entry) == Hash::from_bytes(b"{entry_hash}")
        require witness::blake2b(output_type) == Hash::from_bytes(b"{output_hash}")
        return 0
}}
"#,
        raw_size = raw.len(),
        lock_first = lock[0],
        lock_last = lock[699],
        raw_hash = byte_string_literal(&blake2b_256(raw)),
        lock_hash = byte_string_literal(&blake2b_256(lock)),
        entry_hash = byte_string_literal(&blake2b_256(entry)),
        output_hash = byte_string_literal(&blake2b_256(output_type)),
    )
}

fn bounded_probe_source(constructor: &str, maximum: u64, expression: &str) -> String {
    format!(
        r#"module runtime_views::bounded_witness_probe

action inspect() -> u64 {{
    verification
        let witness_args = witness::args(0)
        let bytes = witness::{constructor}(witness_args, {maximum})
        let observed = {expression}
        return 0
}}
"#
    )
}

fn compile_failure(source: &str) -> cellscript::error::CompileError {
    match compile_with_executable_surface_policy(
        source,
        CompileOptions {
            edition: CellScriptEdition::Edition2027,
            target: Some("riscv64-elf".to_string()),
            target_profile: Some("ckb".to_string()),
            ..Default::default()
        },
        ExecutableSurfacePolicy::DenyFailClosed,
    ) {
        Ok(_) => panic!("source unexpectedly compiled:\n{source}"),
        Err(error) => error,
    }
}

#[test]
fn bounded_witness_owners_stream_large_fields_and_preserve_provenance() {
    let lock = (0..700).map(|index| ((index * 3 + 1) & 0xff) as u8).collect::<Vec<_>>();
    let entry = (0..900).map(|index| ((index * 5 + 2) & 0xff) as u8).collect::<Vec<_>>();
    let output_type = (0..1024).map(|index| ((index * 7 + 3) & 0xff) as u8).collect::<Vec<_>>();
    let witness = packed::WitnessArgs::new_builder()
        .lock(Some(Bytes::copy_from_slice(&lock)).pack())
        .input_type(Some(Bytes::copy_from_slice(&entry)).pack())
        .output_type(Some(Bytes::copy_from_slice(&output_type)).pack())
        .build()
        .as_bytes();
    assert!(witness.len() > 512, "fixture must exercise the streaming path beyond the legacy fixed buffer");

    let result = compile(&bounded_read_source(&witness, &lock, &entry, &output_type));
    let execution = execute_cellscript_script(strip_vm_abi_trailer(&result.artifact_bytes), &bounded_witness_fixture(witness.clone()));
    assert_eq!(execution.exit_code, 0, "all bounded witness owners and hashes must execute: {:?}", execution.captured_debug);
    assert!(result.metadata.runtime.ckb_runtime_features.contains(&"ckb-bounded-witness-view".to_string()));
    assert!(result.metadata.runtime.ckb_runtime_features.contains(&"ckb-blake2b".to_string()));

    for (owner, maximum) in [("raw", 4096), ("lock", 700), ("entry", 900), ("output_type", 1024)] {
        assert!(result.metadata.runtime.transaction_view_handles.iter().any(|handle| {
            handle.handle_type == format!("WitnessBytesView<{owner},{maximum}>")
                && handle.witness_owner.as_deref() == Some(owner)
                && handle.max_bytes == Some(maximum)
                && handle.provenance.source.resolved_source == "Input"
                && handle.provenance.range.kind == "bounded-range"
                && handle.provenance.range.length.max_inclusive == Some(maximum)
        }));
        assert!(result.metadata.runtime.ckb_runtime_accesses.iter().any(|access| {
            access.operation == format!("witness-bounded-{owner}-blake2b")
                && access.provenance.source.resolved_source == "Input"
                && access.provenance.range.kind == "bounded-range"
                && access.provenance.range.length.max_inclusive == Some(maximum)
        }));
    }

    let mut tampered = result.metadata.clone();
    for access in tampered
        .runtime
        .ckb_runtime_accesses
        .iter_mut()
        .chain(tampered.actions.iter_mut().flat_map(|action| action.ckb_runtime_accesses.iter_mut()))
        .filter(|access| access.operation == "witness-bounded-lock-blake2b")
    {
        access.operation = "witness-bounded-lock-unknown".to_string();
    }
    let error = cellscript::validate_compile_metadata(&tampered, result.artifact_format)
        .expect_err("a non-canonical bounded witness runtime operation must not validate");
    assert!(error.message.contains("not canonical"), "unexpected bounded witness metadata error: {error}");

    let mut tampered = result.metadata.clone();
    let handle = tampered
        .runtime
        .transaction_view_handles
        .iter_mut()
        .find(|handle| handle.handle_type == "WitnessBytesView<lock,700>")
        .expect("bounded lock handle");
    handle.provenance.range.length.max_inclusive = Some(699);
    let error = cellscript::validate_compile_metadata(&tampered, result.artifact_format)
        .expect_err("a bounded witness handle range must remain tied to its declared maximum");
    assert!(error.message.contains("bounded witness range"), "unexpected bounded witness handle error: {error}");

    let group_output_source = format!(
        r#"module runtime_views::bounded_group_output

action inspect() -> u64 {{
    verification
        let output_type = witness::bounded_output_type(source::group_output(0), 1024)
        require output_type.size == 1024
        require witness::byte(output_type, 1023) == {last_byte}
        return 0
}}
"#,
        last_byte = output_type[1023],
    );
    let group_output = compile(&group_output_source);
    let execution = execute_cellscript_script(strip_vm_abi_trailer(&group_output.artifact_bytes), &bounded_witness_fixture(witness));
    assert_eq!(execution.exit_code, 0, "GroupOutput witness provenance must remain executable");
    assert!(group_output.metadata.runtime.transaction_view_handles.iter().any(|handle| {
        handle.handle_type == "WitnessBytesView<output_type,1024>"
            && handle.source == "GroupOutput"
            && handle.provenance.source.resolved_source == "GroupOutput"
    }));
}

#[test]
fn bounded_witness_empty_absent_bound_and_range_semantics_fail_closed() {
    let empty = packed::WitnessArgs::new_builder()
        .lock(Some(Bytes::default()).pack())
        .input_type(Some(Bytes::default()).pack())
        .output_type(Some(Bytes::default()).pack())
        .build()
        .as_bytes();
    let empty_hash = byte_string_literal(&blake2b_256(&[]));
    let empty_source = format!(
        r#"module runtime_views::bounded_witness_empty

action inspect() -> u64 {{
    verification
        let witness_args = witness::args(0)
        let lock = witness::bounded_lock(witness_args, 0)
        let entry = witness::bounded_entry(witness_args, 0)
        let output_type = witness::bounded_output_type(witness_args, 0)
        require lock.size == 0
        require entry.size == 0
        require output_type.size == 0
        require witness::blake2b(lock) == Hash::from_bytes(b"{empty_hash}")
        require witness::blake2b(entry) == Hash::from_bytes(b"{empty_hash}")
        require witness::blake2b(output_type) == Hash::from_bytes(b"{empty_hash}")
        return 0
}}
"#
    );
    let result = compile(&empty_source);
    let execution = execute_cellscript_script(strip_vm_abi_trailer(&result.artifact_bytes), &bounded_witness_fixture(empty));
    assert_eq!(execution.exit_code, 0, "Some(empty) must remain distinct from an absent WitnessArgs field");

    let absent = packed::WitnessArgs::new_builder().build().as_bytes();
    for constructor in ["bounded_lock", "bounded_entry", "bounded_output_type"] {
        let result = compile(&bounded_probe_source(constructor, 16, "bytes.size"));
        let execution =
            execute_cellscript_script(strip_vm_abi_trailer(&result.artifact_bytes), &bounded_witness_fixture(absent.clone()));
        assert_eq!(
            execution.exit_code,
            cellscript::runtime_errors::CellScriptRuntimeError::WitnessFieldAbsent.code() as i64,
            "{constructor} must reject an absent field"
        );
    }

    let long_lock = packed::WitnessArgs::new_builder().lock(Some(Bytes::from(vec![7u8; 65])).pack()).build().as_bytes();
    let result = compile(&bounded_probe_source("bounded_lock", 64, "bytes.size"));
    let execution = execute_cellscript_script(strip_vm_abi_trailer(&result.artifact_bytes), &bounded_witness_fixture(long_lock));
    assert_eq!(
        execution.exit_code,
        cellscript::runtime_errors::CellScriptRuntimeError::WitnessBoundExceeded.code() as i64,
        "a field one byte above its declared bound must reject"
    );

    let short_lock = packed::WitnessArgs::new_builder().lock(Some(Bytes::from(vec![1u8; 7])).pack()).build().as_bytes();
    let result = compile(&bounded_probe_source("bounded_lock", 7, "witness::u64_le(bytes, 0)"));
    let execution = execute_cellscript_script(strip_vm_abi_trailer(&result.artifact_bytes), &bounded_witness_fixture(short_lock));
    assert_eq!(
        execution.exit_code,
        cellscript::runtime_errors::CellScriptRuntimeError::BoundsCheckFailed.code() as i64,
        "an exact read beyond the logical field view must reject"
    );
}

#[test]
fn bounded_witness_rejects_malformed_tables_and_invalid_static_bounds() {
    let result = compile(&bounded_probe_source("bounded_lock", 32, "bytes.size"));
    let malformed_total = Bytes::from(vec![17, 0, 0, 0, 16, 0, 0, 0, 16, 0, 0, 0, 16, 0, 0, 0]);
    let execution = execute_cellscript_script(strip_vm_abi_trailer(&result.artifact_bytes), &bounded_witness_fixture(malformed_total));
    assert_eq!(
        execution.exit_code,
        cellscript::runtime_errors::CellScriptRuntimeError::WitnessMalformed.code() as i64,
        "a mismatched WitnessArgs total_size must reject"
    );

    let truncated_offset = Bytes::from(vec![16, 0, 0, 0, 16, 0, 0, 0, 16, 0, 0, 0, 17, 0, 0, 0]);
    let execution =
        execute_cellscript_script(strip_vm_abi_trailer(&result.artifact_bytes), &bounded_witness_fixture(truncated_offset));
    assert_eq!(
        execution.exit_code,
        cellscript::runtime_errors::CellScriptRuntimeError::WitnessFieldTruncated.code() as i64,
        "a WitnessArgs field offset beyond total_size must reject"
    );

    for source in [
        bounded_probe_source("bounded_raw", 65537, "bytes.size"),
        r#"module runtime_views::bounded_dynamic_limit

action inspect(witness maximum: u64) -> u64 {
    verification
        let witness_args = witness::args(0)
        let bytes = witness::bounded_raw(witness_args, maximum)
        return bytes.size
}
"#
        .to_string(),
    ] {
        let error = compile_failure(&source);
        assert!(error.message.contains("maximum_bytes"), "unexpected bounded-witness diagnostic: {error}");
    }

    let error = compile_failure(
        r#"module runtime_views::unbounded_witness_hash

action inspect() -> u64 {
    verification
        let witness_args = witness::args(0)
        let digest = witness::blake2b(witness_args)
        return 0
}
"#,
    );
    assert!(error.message.contains("bounded witness byte view"), "unexpected unbounded hash diagnostic: {error}");
}
