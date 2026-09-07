use cellscript_ckb_adapter::{place_entry_witness_payload_before_signing, EntryWitnessPlacementAbi};
use ckb_testtool::ckb_hash::blake2b_256;
use ckb_testtool::ckb_types::bytes::Bytes;
use ckb_testtool::ckb_types::packed;
use ckb_testtool::ckb_types::prelude::{Builder, Entity};
use sha2::{Digest, Sha256};

#[path = "support/ckb_script_runner.rs"]
#[allow(dead_code)]
mod ckb_script_runner;

use ckb_script_runner::{build_simple_fixture, compile_cellscript_source_to_elf, execute_cellscript_script, FixtureCell};

const SHA256_MERKLE_PROGRAM: &str = r#"
module sha256_merkle_vm

action verify(
    witness leaf: Hash,
    witness other: Hash,
    witness siblings: [Hash; 16],
    witness expected_sha256: Hash,
    witness expected_sha256d: Hash,
    witness expected_pair: Hash,
    witness expected_merkle_root: Hash,
) -> u64 {
    verification
        require ckb::hash_sha256(leaf) == expected_sha256
        require ckb::hash_sha256d(leaf) == expected_sha256d
        require ckb::hash_sha256d_pair(leaf, other) == expected_pair
        ckb::require_sha256d_merkle_root(leaf, siblings, 1, 0, expected_merkle_root)
        return 0
}
"#;

const BOUNDED_CELL_DEP_PROGRAM: &str = r#"
module bounded_cell_dep_vm

action verify(witness expected_data_hash: Hash) -> u64 {
    verification
        ckb::require_bounded_cell_dep_data_hash(8, expected_data_hash)
        ckb::require_cell_data_hash(source::cell_dep(0), expected_data_hash)
        return 0
}
"#;

const BLAKE2B_SHARED_COMPRESSION_PROGRAM: &str = r#"
module blake2b_shared_compression_vm

action verify(
    witness input: Hash,
    witness expected_hash32: Hash,
    witness expected_empty: Hash,
    witness expected_128: Hash,
    witness expected_129: Hash,
) -> u64 {
    verification
        require hash_blake2b(input) == expected_hash32
        require ckb::cell_data_blake2b_span(source::input(0), 0, 0) == expected_empty
        require ckb::cell_data_blake2b_span(source::input(0), 0, 128) == expected_128
        require ckb::cell_data_blake2b_span(source::input(0), 0, 129) == expected_129
        return 0
}
"#;

const CACHED_EXACT_READ_PROGRAM: &str = r#"
module cached_exact_read_vm

action verify() -> u64 {
    verification
        let input = source::input(0)
        require ckb::cell_data_u8(input, 0) == 11
        require ckb::cell_data_u32_le(input, 1) == 2675594544
        require ckb::cell_data_u64_le(input, 248) == 16627743335522306275
        require ckb::cell_data_u8(input, 256) == 11
        require ckb::cell_data_u64_le(input, 300) == 7657563007424236647
        require witness::byte(input, 0) == 7
        require witness::u32_le(input, 1) == 3685118268
        require witness::u64_le(input, 248) == 15176400891835683935
        require witness::byte(input, 256) == 7
        require witness::u64_le(input, 300) == 10835991621062711331
        require ckb::cell_lock_size(input) == 53
        require ckb::cell_lock_u8(input, 0) == 53
        require ckb::cell_lock_u8(input, 4) == 16
        require ckb::cell_lock_u8(input, 48) == 1
        let output = source::output(0)
        require ckb::cell_type_size(output) == 53
        require ckb::cell_type_u8(output, 0) == 53
        require ckb::cell_type_u8(output, 8) == 48
        require ckb::cell_type_u8(output, 48) == 1
        // Revisit both entries after alternating source kinds: the cache key
        // must include field kind and SourceView, not merely the byte offset.
        require ckb::cell_lock_u8(input, 48) == 1
        require ckb::cell_type_u8(output, 48) == 1
        return 0
}
"#;

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn sha256d(bytes: &[u8]) -> [u8; 32] {
    sha256(&sha256(bytes))
}

fn canonical_entry_witness(payload: Vec<u8>) -> Bytes {
    let base = packed::WitnessArgs::new_builder().build();
    place_entry_witness_payload_before_signing(&base, EntryWitnessPlacementAbi::WitnessArgsInputTypeV2, Bytes::from(payload))
        .expect("place CellScript entry payload in WitnessArgs.input_type")
        .as_bytes()
}

fn sha256_merkle_witness(expected_root: [u8; 32]) -> Bytes {
    let leaf = std::array::from_fn::<_, 32, _>(|index| index as u8);
    let other = std::array::from_fn::<_, 32, _>(|index| (0xff - index) as u8);
    let expected_sha256 = sha256(&leaf);
    let expected_sha256d = sha256d(&leaf);
    let mut pair_preimage = Vec::with_capacity(64);
    pair_preimage.extend_from_slice(&leaf);
    pair_preimage.extend_from_slice(&other);
    let expected_pair = sha256d(&pair_preimage);

    let mut witness = b"CSARGv1\0".to_vec();
    witness.extend_from_slice(&leaf);
    witness.extend_from_slice(&other);
    witness.extend_from_slice(&other);
    witness.resize(8 + 32 + 32 + 16 * 32, 0);
    witness.extend_from_slice(&expected_sha256);
    witness.extend_from_slice(&expected_sha256d);
    witness.extend_from_slice(&expected_pair);
    witness.extend_from_slice(&expected_root);
    canonical_entry_witness(witness)
}

#[test]
fn bounded_sha256_sha256d_and_merkle_execute_in_ckb_vm() {
    let leaf = std::array::from_fn::<_, 32, _>(|index| index as u8);
    let other = std::array::from_fn::<_, 32, _>(|index| (0xff - index) as u8);
    let mut pair_preimage = Vec::with_capacity(64);
    pair_preimage.extend_from_slice(&leaf);
    pair_preimage.extend_from_slice(&other);
    let expected_pair = sha256d(&pair_preimage);

    let witness = sha256_merkle_witness(expected_pair);

    let elf = compile_cellscript_source_to_elf(SHA256_MERKLE_PROGRAM, "verify", None);
    let mut fixture = build_simple_fixture(Bytes::default(), 1, 1);
    fixture.witnesses = vec![witness];
    let result = execute_cellscript_script(&elf, &fixture);

    assert_eq!(result.exit_code, 0, "bounded SHA-256/SHA256d/Merkle helpers failed in CKB VM: {:?}", result.captured_debug);
    assert!(result.cycles > 0);
}

#[test]
fn bounded_merkle_rejects_wrong_root_in_ckb_vm() {
    let elf = compile_cellscript_source_to_elf(SHA256_MERKLE_PROGRAM, "verify", None);
    let mut fixture = build_simple_fixture(Bytes::default(), 1, 1);
    fixture.witnesses = vec![sha256_merkle_witness([0x5a; 32])];
    let result = execute_cellscript_script(&elf, &fixture);

    assert_eq!(result.exit_code, 64, "wrong Merkle root must fail closed with the stable runtime code: {:?}", result.captured_debug);
}

#[test]
fn bounded_cell_dep_scan_and_exact_identity_execute_in_ckb_vm() {
    let dep_data = Bytes::from_static(b"cellscript-verifier-package-v0");
    let expected_data_hash = blake2b_256(&dep_data);
    let mut witness = b"CSARGv1\0".to_vec();
    witness.extend_from_slice(&expected_data_hash);

    let elf = compile_cellscript_source_to_elf(BOUNDED_CELL_DEP_PROGRAM, "verify", None);
    let mut fixture = build_simple_fixture(Bytes::default(), 1, 1);
    fixture.witnesses = vec![canonical_entry_witness(witness)];
    fixture.cell_deps.push(FixtureCell { capacity: 0, type_script: None, data: dep_data });
    let result = execute_cellscript_script(&elf, &fixture);

    assert_eq!(result.exit_code, 0, "bounded CellDep scan/exact identity helpers failed in CKB VM: {:?}", result.captured_debug);
}

#[test]
fn bounded_cell_dep_scan_rejects_missing_dep_in_ckb_vm() {
    let expected_data_hash = blake2b_256(b"missing-cell-dep");
    let mut witness = b"CSARGv1\0".to_vec();
    witness.extend_from_slice(&expected_data_hash);

    let elf = compile_cellscript_source_to_elf(BOUNDED_CELL_DEP_PROGRAM, "verify", None);
    let mut fixture = build_simple_fixture(Bytes::default(), 1, 1);
    fixture.witnesses = vec![canonical_entry_witness(witness)];
    let result = execute_cellscript_script(&elf, &fixture);

    assert_eq!(result.exit_code, 63, "missing CellDep must fail closed with the stable runtime code: {:?}", result.captured_debug);
}

#[test]
fn shared_blake2b_compression_matches_host_vectors_in_ckb_vm() {
    let input = std::array::from_fn::<_, 32, _>(|index| (index * 17 + 3) as u8);
    let data = (0..129).map(|index| ((index * 131 + index / 17 + 0x80) & 255) as u8).collect::<Vec<_>>();
    let mut witness = b"CSARGv1\0".to_vec();
    for digest in [blake2b_256(input), blake2b_256([]), blake2b_256(&data[..128]), blake2b_256(&data)] {
        witness.extend_from_slice(&digest);
    }
    witness.splice(8..8, input);

    let elf = compile_cellscript_source_to_elf(BLAKE2B_SHARED_COMPRESSION_PROGRAM, "verify", None);
    let mut fixture = build_simple_fixture(Bytes::default(), 1, 1);
    fixture.inputs[0].data = Bytes::from(data);
    fixture.witnesses = vec![canonical_entry_witness(witness)];
    let result = execute_cellscript_script(&elf, &fixture);

    assert_eq!(result.exit_code, 0, "shared BLAKE2b compression disagreed with host vectors: {:?}", result.captured_debug);
    assert!(result.cycles > 0);
}

#[test]
fn blake2b_runtime_emits_one_shared_compression_body() {
    let result = cellscript::compile(
        BLAKE2B_SHARED_COMPRESSION_PROGRAM,
        cellscript::CompileOptions {
            target: Some("riscv64".to_string()),
            target_profile: Some("ckb".to_string()),
            ..Default::default()
        },
    )
    .expect("compile shared BLAKE2b assembly");
    let assembly = String::from_utf8(result.artifact_bytes).expect("RISC-V assembly is UTF-8");

    assert_eq!(assembly.matches("__cellscript_blake2b_compress:").count(), 1);
    assert!(assembly.matches("call __cellscript_blake2b_compress").count() >= 2);
}

#[test]
fn cached_exact_reads_preserve_data_witness_script_kind_and_window_boundaries() {
    let data = (0..320).map(|index| ((index * 37 + 11) & 255) as u8).collect::<Vec<_>>();
    let witness = (0..320).map(|index| ((index * 53 + 7) & 255) as u8).collect::<Vec<_>>();
    let elf = compile_cellscript_source_to_elf(CACHED_EXACT_READ_PROGRAM, "verify", None);
    let mut fixture = build_simple_fixture(Bytes::default(), 1, 1);
    fixture.inputs[0].data = Bytes::from(data);
    fixture.witnesses = vec![Bytes::from(witness)];
    let result = execute_cellscript_script(&elf, &fixture);

    assert_eq!(result.exit_code, 0, "cached exact reads changed source identity or byte order: {:?}", result.captured_debug);
    assert!(result.cycles > 0);
}
