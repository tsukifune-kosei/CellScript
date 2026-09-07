use cellscript::{ckb_abi, ckb_blake2b256, compile, stdlib::StdLib, CompileOptions, TargetProfile};
use ckb_std::ckb_constants::{self as std_consts, CellField, HeaderField, InputField, Place, Source};
use ckb_std::since::{EpochNumberWithFraction, Since};
use ckb_testtool::ckb_types::{
    bytes::Bytes,
    core::{Capacity, ScriptHashType, TransactionBuilder},
    packed,
    prelude::*,
};

#[test]
fn ckb_abi_syscall_constants_match_ckb_std() {
    assert_eq!(ckb_abi::syscall::EXIT, std_consts::SYS_EXIT);
    assert_eq!(ckb_abi::syscall::VM_VERSION, std_consts::SYS_VM_VERSION);
    assert_eq!(ckb_abi::syscall::CURRENT_CYCLES, std_consts::SYS_CURRENT_CYCLES);
    assert_eq!(ckb_abi::syscall::EXEC, std_consts::SYS_EXEC);
    assert_eq!(ckb_abi::syscall::LOAD_TRANSACTION, std_consts::SYS_LOAD_TRANSACTION);
    assert_eq!(ckb_abi::syscall::LOAD_SCRIPT, std_consts::SYS_LOAD_SCRIPT);
    assert_eq!(ckb_abi::syscall::LOAD_TX_HASH, std_consts::SYS_LOAD_TX_HASH);
    assert_eq!(ckb_abi::syscall::LOAD_SCRIPT_HASH, std_consts::SYS_LOAD_SCRIPT_HASH);
    assert_eq!(ckb_abi::syscall::LOAD_CELL, std_consts::SYS_LOAD_CELL);
    assert_eq!(ckb_abi::syscall::LOAD_HEADER, std_consts::SYS_LOAD_HEADER);
    assert_eq!(ckb_abi::syscall::LOAD_INPUT, std_consts::SYS_LOAD_INPUT);
    assert_eq!(ckb_abi::syscall::LOAD_WITNESS, std_consts::SYS_LOAD_WITNESS);
    assert_eq!(ckb_abi::syscall::LOAD_CELL_BY_FIELD, std_consts::SYS_LOAD_CELL_BY_FIELD);
    assert_eq!(ckb_abi::syscall::LOAD_HEADER_BY_FIELD, std_consts::SYS_LOAD_HEADER_BY_FIELD);
    assert_eq!(ckb_abi::syscall::LOAD_INPUT_BY_FIELD, std_consts::SYS_LOAD_INPUT_BY_FIELD);
    assert_eq!(ckb_abi::syscall::LOAD_CELL_DATA_AS_CODE, std_consts::SYS_LOAD_CELL_DATA_AS_CODE);
    assert_eq!(ckb_abi::syscall::LOAD_CELL_DATA, std_consts::SYS_LOAD_CELL_DATA);
    assert_eq!(ckb_abi::syscall::LOAD_BLOCK_EXTENSION, std_consts::SYS_LOAD_BLOCK_EXTENSION);
    assert_eq!(ckb_abi::syscall::DEBUG, std_consts::SYS_DEBUG);
    assert_eq!(ckb_abi::syscall::SPAWN, std_consts::SYS_SPAWN);
    assert_eq!(ckb_abi::syscall::WAIT, std_consts::SYS_WAIT);
    assert_eq!(ckb_abi::syscall::PROCESS_ID, std_consts::SYS_PROCESS_ID);
    assert_eq!(ckb_abi::syscall::PIPE, std_consts::SYS_PIPE);
    assert_eq!(ckb_abi::syscall::WRITE, std_consts::SYS_WRITE);
    assert_eq!(ckb_abi::syscall::READ, std_consts::SYS_READ);
    assert_eq!(ckb_abi::syscall::INHERITED_FDS, std_consts::SYS_INHERITED_FDS);
    assert_eq!(ckb_abi::syscall::CLOSE, std_consts::SYS_CLOSE);
}

#[test]
fn ckb_abi_source_and_field_constants_match_ckb_std() {
    assert_eq!(ckb_abi::source::INPUT, Source::Input as u64);
    assert_eq!(ckb_abi::source::OUTPUT, Source::Output as u64);
    assert_eq!(ckb_abi::source::CELL_DEP, Source::CellDep as u64);
    assert_eq!(ckb_abi::source::HEADER_DEP, Source::HeaderDep as u64);
    assert_eq!(ckb_abi::source::GROUP_INPUT, Source::GroupInput as u64);
    assert_eq!(ckb_abi::source::GROUP_OUTPUT, Source::GroupOutput as u64);

    assert_eq!(ckb_abi::cell_field::CAPACITY, CellField::Capacity as u64);
    assert_eq!(ckb_abi::cell_field::DATA_HASH, CellField::DataHash as u64);
    assert_eq!(ckb_abi::cell_field::LOCK, CellField::Lock as u64);
    assert_eq!(ckb_abi::cell_field::LOCK_HASH, CellField::LockHash as u64);
    assert_eq!(ckb_abi::cell_field::TYPE, CellField::Type as u64);
    assert_eq!(ckb_abi::cell_field::TYPE_HASH, CellField::TypeHash as u64);
    assert_eq!(ckb_abi::cell_field::OCCUPIED_CAPACITY, CellField::OccupiedCapacity as u64);

    assert_eq!(ckb_abi::header_field::EPOCH_NUMBER, HeaderField::EpochNumber as u64);
    assert_eq!(ckb_abi::header_field::EPOCH_START_BLOCK_NUMBER, HeaderField::EpochStartBlockNumber as u64);
    assert_eq!(ckb_abi::header_field::EPOCH_LENGTH, HeaderField::EpochLength as u64);

    assert_eq!(ckb_abi::input_field::OUT_POINT, InputField::OutPoint as u64);
    assert_eq!(ckb_abi::input_field::SINCE, InputField::Since as u64);

    assert_eq!(ckb_abi::place::CELL, Place::Cell as u64);
    assert_eq!(ckb_abi::place::WITNESS, Place::Witness as u64);
}

#[test]
fn cellscript_source_view_decodes_to_ckb_std_source_values() {
    for (view, expected_source) in [
        (ckb_abi::source_view::INPUT, Source::Input as u64),
        (ckb_abi::source_view::OUTPUT, Source::Output as u64),
        (ckb_abi::source_view::CELL_DEP, Source::CellDep as u64),
        (ckb_abi::source_view::HEADER_DEP, Source::HeaderDep as u64),
        (ckb_abi::source_view::GROUP_INPUT, Source::GroupInput as u64),
        (ckb_abi::source_view::GROUP_OUTPUT, Source::GroupOutput as u64),
    ] {
        for index in [0, 13, ckb_abi::source_view::SHIFT - 1] {
            let encoded = ckb_abi::encode_source_view(view, index).expect("valid SourceView");
            assert_eq!(ckb_abi::decode_source_view(encoded), Some((expected_source, index)));
        }
    }
    assert!(ckb_abi::encode_source_view(99, 0).is_none());
    assert!(ckb_abi::encode_source_view(ckb_abi::source_view::INPUT, ckb_abi::source_view::SHIFT).is_none());
    assert!(ckb_abi::decode_source_view(99 * ckb_abi::source_view::SHIFT).is_none());
}

#[test]
fn ckb_abi_since_epoch_encoding_matches_ckb_std() {
    let epoch = EpochNumberWithFraction::new(42, 1, 10);
    let expected_epoch = 42 | (1 << 24) | (10 << 40);
    assert_eq!(epoch.full_value(), expected_epoch);
    assert_eq!(ckb_abi::since::EPOCH_NUMBER_WITH_FRACTION_FLAG | expected_epoch, Since::from_epoch(epoch, true).as_u64());
    assert_eq!(
        ckb_abi::since::RELATIVE_FLAG | ckb_abi::since::EPOCH_NUMBER_WITH_FRACTION_FLAG | expected_epoch,
        Since::from_epoch(epoch, false).as_u64()
    );

    assert_eq!(ckb_abi::since::BLOCK_NUMBER_FLAG | 77, Since::from_block_number(77, true).expect("block since").as_u64());
    assert_eq!(
        ckb_abi::since::RELATIVE_FLAG | ckb_abi::since::BLOCK_NUMBER_FLAG | 77,
        Since::from_block_number(77, false).expect("relative block since").as_u64()
    );
    assert_eq!(ckb_abi::since::TIMESTAMP_FLAG | 88, Since::from_timestamp(88, true).expect("timestamp since").as_u64());
}

#[test]
fn ckb_abi_since_malformed_cases_match_ckb_std() {
    assert!(EpochNumberWithFraction::create(42, 1, 10).is_some());
    assert!(EpochNumberWithFraction::create(ckb_abi::since::EPOCH_NUMBER_BOUND, 0, 1).is_none());
    assert!(EpochNumberWithFraction::create(42, ckb_abi::since::EPOCH_FRACTION_BOUND, 1).is_none());
    assert!(EpochNumberWithFraction::create(42, 0, 0).is_none());
    assert!(EpochNumberWithFraction::create(42, 10, 10).is_none());

    assert!(Since::from_block_number(ckb_abi::since::VALUE_MASK, true).is_some());
    assert!(Since::from_block_number(ckb_abi::since::VALUE_MASK + 1, true).is_none());
    assert!(Since::from_timestamp(ckb_abi::since::VALUE_MASK, true).is_some());
    assert!(Since::from_timestamp(ckb_abi::since::VALUE_MASK + 1, true).is_none());
    assert_eq!(ckb_abi::since::TIMESTAMP_VALUE_BOUND, u64::MAX / 1_000 + 1);

    assert!(!Since::new(ckb_abi::since::REMAIN_FLAGS_BITS | 1).flags_is_valid());
    assert!(!Since::new(ckb_abi::since::METRIC_TYPE_FLAG_MASK | 1).flags_is_valid());
}

#[test]
fn ckb_type_id_lifecycle_rules_match_ckb_std_type_id_contract() {
    let _validate_type_id: fn(&[u8]) -> Result<(), ckb_std::error::SysError> = ckb_std::type_id::validate_type_id;
    let _check_type_id: fn(usize, usize) -> Result<(), ckb_std::error::SysError> = ckb_std::type_id::check_type_id;

    use ckb_abi::type_id::Lifecycle;
    assert_eq!(ckb_abi::type_id::lifecycle_for_group_counts(0, 1), Some(Lifecycle::Mint));
    assert_eq!(ckb_abi::type_id::lifecycle_for_group_counts(1, 1), Some(Lifecycle::Continue));
    assert_eq!(ckb_abi::type_id::lifecycle_for_group_counts(1, 0), Some(Lifecycle::Burn));
    for invalid in [(0, 0), (0, 2), (1, 2), (2, 0), (2, 1), (2, 2)] {
        assert_eq!(ckb_abi::type_id::lifecycle_for_group_counts(invalid.0, invalid.1), None, "{invalid:?}");
    }
}

#[test]
fn ckb_type_id_args_hash_matches_ckb_std_contract() {
    let out_point = packed::OutPoint::new_builder().tx_hash([0x11u8; 32].pack()).index(7u32).build();
    let input = packed::CellInput::new_builder().previous_output(out_point).since(42u64).build();
    let output_index = 5u64;

    let actual = ckb_abi::type_id::args_from_first_input_and_output_index(input.as_slice(), output_index);
    let mut expected_material = input.as_slice().to_vec();
    expected_material.extend_from_slice(&output_index.to_le_bytes());
    assert_eq!(actual, ckb_blake2b256(&expected_material));

    let mut big_endian_material = input.as_slice().to_vec();
    big_endian_material.extend_from_slice(&output_index.to_be_bytes());
    assert_ne!(actual, ckb_blake2b256(&big_endian_material));
}

#[test]
fn generated_stdlib_syscall_surface_uses_central_ckb_abi_table() {
    let asm = StdLib::generate_assembly_for_target_profile(TargetProfile::Ckb);
    for syscall in [
        ckb_abi::syscall::LOAD_TX_HASH,
        ckb_abi::syscall::LOAD_SCRIPT_HASH,
        ckb_abi::syscall::LOAD_CELL,
        ckb_abi::syscall::LOAD_HEADER,
        ckb_abi::syscall::LOAD_INPUT,
        ckb_abi::syscall::LOAD_WITNESS,
        ckb_abi::syscall::LOAD_SCRIPT,
        ckb_abi::syscall::LOAD_CELL_BY_FIELD,
        ckb_abi::syscall::LOAD_CELL_DATA,
        ckb_abi::syscall::CURRENT_CYCLES,
        ckb_abi::syscall::DEBUG,
        ckb_abi::syscall::LOAD_HEADER_BY_FIELD,
        ckb_abi::syscall::LOAD_INPUT_BY_FIELD,
    ] {
        assert!(asm.contains(&format!("li a7, {syscall}")), "generated stdlib missed syscall {syscall}:\n{asm}");
    }
    assert!(asm.contains(&format!("li a4, {}  # Source::GroupInput", ckb_abi::source::GROUP_INPUT)), "{asm}");
    assert!(!asm.contains("li a4, 256"), "generated stdlib must not use the old local GroupInput pseudo-value:\n{asm}");
}

#[test]
fn occupied_capacity_lowering_uses_ckb_occupied_capacity_field() {
    let source = r#"
module compat::occupied

action occupied() -> u64 {
    verification
        return ckb::cell_occupied_capacity(source::input(0))
}
"#;
    let result = compile(source, CompileOptions::default()).expect("compile occupied capacity helper");
    let assembly = std::str::from_utf8(&result.artifact_bytes).expect("assembly utf-8");
    let helper = assembly_section(assembly, "__ckb_cell_occupied_capacity:", "__ckb_cell_unoccupied_capacity:");
    assert!(helper.contains("CellField::OccupiedCapacity"), "{helper}");
    assert!(helper.contains(&format!("li a5, {}", ckb_abi::cell_field::OCCUPIED_CAPACITY)), "{helper}");
    assert!(helper.contains(&format!("li a7, {}", ckb_abi::syscall::LOAD_CELL_BY_FIELD)), "{helper}");
    assert!(!helper.contains(&format!("li a7, {}", ckb_abi::syscall::LOAD_CELL_DATA)), "{helper}");
}

#[test]
fn ckb_types_occupied_capacity_matches_cellscript_field_contract() {
    let lock = script([1u8; 32], ScriptHashType::Data1, vec![2u8; 20]);
    let type_script = script([3u8; 32], ScriptHashType::Type, vec![4u8; 16]);
    let output = packed::CellOutput::new_builder()
        .capacity::<packed::Uint64>(1_000_000_000_000u64.pack())
        .lock(lock)
        .type_(Some(type_script).pack())
        .build();
    let data = Bytes::from(vec![9u8; 37]);
    let data_capacity = Capacity::bytes(data.len()).expect("data capacity");
    let occupied = output.occupied_capacity(data_capacity).expect("ckb occupied capacity").as_u64();
    assert!(occupied > 0);
    assert_eq!(ckb_abi::cell_field::OCCUPIED_CAPACITY, CellField::OccupiedCapacity as u64);
}

#[test]
fn adapter_headless_draft_materializes_to_packed_ckb_transaction_shape() {
    let dep_out_point = packed::OutPoint::new_builder().tx_hash([0x44u8; 32].pack()).index(0u32).build();
    let cell_dep = packed::CellDep::new_builder().out_point(dep_out_point.clone()).build();
    let lock = script([0x55u8; 32], ScriptHashType::Data1, vec![0x66u8; 20]);
    let type_script = script([0x77u8; 32], ScriptHashType::Type, vec![0x88u8; 32]);
    let output = packed::CellOutput::new_builder().capacity(100_000_000_000u64).lock(lock).type_(Some(type_script).pack()).build();
    let output_data = Bytes::from(vec![0x99u8; 24]);
    let witness = packed::WitnessArgs::new_builder().input_type(Some(Bytes::from(vec![0x11u8; 8])).pack()).build();

    let tx = TransactionBuilder::default()
        .cell_dep(cell_dep)
        .output(output.clone())
        .output_data(output_data.clone().pack())
        .witness(witness.as_bytes().pack())
        .build();

    let occupied =
        output.occupied_capacity(Capacity::bytes(output_data.len()).expect("output data capacity")).expect("occupied capacity");
    assert!(occupied.as_u64() > output_data.len() as u64);
    assert!(tx.data().as_slice().len() > witness.as_slice().len());
}

#[test]
fn witness_args_table_layout_matches_ckb_types_witness_args() {
    let witness = packed::WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0x11u8; 32])).pack())
        .input_type(Some(Bytes::from(vec![0x22u8; 8])).pack())
        .output_type(Some(Bytes::from(vec![0x33u8; 16])).pack())
        .build();
    let bytes = witness.as_slice();
    let ranges = witness_args_field_ranges(bytes).expect("WitnessArgs table ranges");
    assert_eq!(&bytes[ranges[0].0 + 4..ranges[0].1], &[0x11u8; 32]);
    assert_eq!(&bytes[ranges[1].0 + 4..ranges[1].1], &[0x22u8; 8]);
    assert_eq!(&bytes[ranges[2].0 + 4..ranges[2].1], &[0x33u8; 16]);

    let empty = packed::WitnessArgs::new_builder().build();
    let empty_ranges = witness_args_field_ranges(empty.as_slice()).expect("empty WitnessArgs ranges");
    assert_eq!(empty_ranges[0], (16, 16));
    assert_eq!(empty_ranges[1], (16, 16));
    assert_eq!(empty_ranges[2], (16, 16));
}

#[test]
fn witness_args_table_layout_rejects_malformed_tables() {
    let valid = packed::WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0x11u8; 32])).pack())
        .input_type(Some(Bytes::from(vec![0x22u8; 8])).pack())
        .build();
    let bytes = valid.as_slice();

    assert!(witness_args_field_ranges(&bytes[..15]).is_err());

    let mut total_mismatch = bytes.to_vec();
    total_mismatch[0..4].copy_from_slice(&(bytes.len() as u32 + 1).to_le_bytes());
    assert!(witness_args_field_ranges(&total_mismatch).is_err());

    let mut non_monotonic = bytes.to_vec();
    non_monotonic[8..12].copy_from_slice(&(15u32).to_le_bytes());
    assert!(witness_args_field_ranges(&non_monotonic).is_err());

    let mut offset_beyond = bytes.to_vec();
    offset_beyond[12..16].copy_from_slice(&(bytes.len() as u32 + 4).to_le_bytes());
    assert!(witness_args_field_ranges(&offset_beyond).is_err());

    let mut trailing = bytes.to_vec();
    trailing.push(0xff);
    assert!(witness_args_field_ranges(&trailing).is_err());
}

fn script(code_hash: [u8; 32], hash_type: ScriptHashType, args: Vec<u8>) -> packed::Script {
    packed::Script::new_builder().code_hash(code_hash.pack()).hash_type(hash_type).args(Bytes::from(args).pack()).build()
}

fn assembly_section<'a>(assembly: &'a str, start: &str, end: &str) -> &'a str {
    let start_index = assembly.find(start).expect("section start");
    let tail = &assembly[start_index..];
    let end_index = tail.find(end).unwrap_or(tail.len());
    &tail[..end_index]
}

fn witness_args_field_ranges(bytes: &[u8]) -> Result<[(usize, usize); 3], String> {
    if bytes.len() < 16 {
        return Err("WitnessArgs table shorter than 16 bytes".to_string());
    }
    let total = read_u32_le(bytes, 0)? as usize;
    if total != bytes.len() {
        return Err("WitnessArgs total_size mismatch".to_string());
    }
    let offsets = [read_u32_le(bytes, 4)? as usize, read_u32_le(bytes, 8)? as usize, read_u32_le(bytes, 12)? as usize];
    if offsets[0] != 16 || offsets[1] < offsets[0] || offsets[2] < offsets[1] || total < offsets[2] {
        return Err("WitnessArgs offsets malformed".to_string());
    }
    Ok([(offsets[0], offsets[1]), (offsets[1], offsets[2]), (offsets[2], total)])
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Result<u32, String> {
    let end = offset.checked_add(4).ok_or_else(|| "offset overflow".to_string())?;
    let slice = bytes.get(offset..end).ok_or_else(|| "u32 out of bounds".to_string())?;
    Ok(u32::from_le_bytes(slice.try_into().expect("slice length checked")))
}
