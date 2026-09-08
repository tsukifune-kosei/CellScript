use cellscript_ckb_adapter::{place_entry_witness_payload_before_signing, EntryWitnessPlacementAbi};
use ckb_sdk::{
    constants::MultisigScript,
    traits::SecpCkbRawKeySigner,
    types::ScriptGroup,
    unlock::{MultisigConfig, ScriptSignError, ScriptSigner, SecpMultisigScriptSigner},
    SECP256K1,
};
use ckb_testtool::{
    ckb_hash::blake2b_256,
    ckb_types::{
        bytes::Bytes,
        core::{DepType, TransactionBuilder},
        packed,
        prelude::{Builder, Entity, Pack},
        H160,
    },
    context::Context,
};
use secp256k1::{PublicKey, SecretKey};

#[path = "support/ckb_script_runner.rs"]
#[allow(dead_code)]
mod ckb_script_runner;

use ckb_script_runner::{
    build_simple_fixture, compile_cellscript_source_to_elf, deterministic_always_success_lock_hash, execute_cellscript_script,
};

const PARAMETERIZED_ENTRY: &str = r#"
module entry_witness_abi

action verify(witness expected: u64) -> u64 {
    verification
        require expected == 42
        return 0
}
"#;

const ALWAYS_SUCCESS_LOCK: &str = r#"
module entry_witness_always_success

action always_success() -> u64 {
    verification
        return 0
}
"#;

const LOOP_CONTROL_ENTRY: &str = r#"
module loop_control_entry

action verify() -> u64 {
    verification
        let mut total: u64 = 0
        label outer: for i in 0..4 {
            for j in 0..4 {
                if j == 0 {
                    continue
                }
                if i == 2 {
                    break outer
                }
                total += 1
            }
        }
        require total == 6
        return 0
}
"#;

const BOUNDED_COLLECTION_FAIL_CLOSED_ENTRY: &str = r#"
module bounded_collection_fail_closed_entry

resource Token has store, consume {
    amount: u64
    memo: String
}

action verify(input inputs: BoundedCellSet<Token, 2>) -> u64 {
    verification
        consume_each token in inputs {
            require false
            require token.amount > 0
        }
        return 0
}
"#;

const BOUNDED_CONSUME_RUNTIME_ENTRY: &str = r#"
module bounded_consume_runtime_entry

resource Token has store, consume {
    amount: u64
}

action verify(input inputs: BoundedCellSet<Token, 2>) -> u64 {
    verification
        consume_each token in inputs {
            require token.amount > 0
        }
        return 0
}
"#;

const BOUNDED_CREATE_FAIL_CLOSED_ENTRY: &str = r#"
module bounded_create_fail_closed_entry

struct Plan {
    amount: u64
}

resource Token has store, create {
    amount: u64
}

action verify(witness plans: BoundedList<Plan, 2>) -> u64 {
    verification
        create_each plan in plans {
            require false
            create Token { amount: plan.amount }
        }
        return 0
}
"#;

const BOUNDED_CREATE_RUNTIME_ENTRY: &str = r#"
module bounded_create_runtime_entry

struct Plan {
    owner: Address
    amount: u64
}

resource Token has store, create
with_capacity_floor(10000000000)
{
    amount: u64
}

action verify(witness plans: BoundedList<Plan, 2>) -> u64 {
    verification
        create_each plan in plans {
            require plan.amount > 0
            create Token { amount: plan.amount } with_lock(plan.owner)
        }
        return 0
}
"#;

const BATCH_CLAIM_EXAMPLE: &str = include_str!("../examples/language/batches/batch_claim.cell");
const ATOMIC_ORDER_SETTLEMENT_EXAMPLE: &str = include_str!("../examples/language/batches/atomic_order_settlement.cell");
const CELL_MERGE_EXAMPLE: &str = include_str!("../examples/language/batches/cell_merge.cell");
const BRIDGE_ROLLUP_BATCH_EXAMPLE: &str = include_str!("../examples/language/batches/bridge_rollup_batch.cell");

const U128_DIV_REM_ENTRY: &str = r#"
module entry_witness_u128_div_rem

action verify(
    witness left: u128,
    witness right: u128,
    witness expected_quotient: u128,
    witness expected_remainder: u128,
) -> u64 {
    verification
        require left / right == expected_quotient
        require left % right == expected_remainder
        return 0
}
"#;

const SCALAR_DIV_REM_ENTRY: &str = r#"
module entry_witness_scalar_div_rem

action verify(
    witness left: u64,
    witness right: u64,
    witness expected_quotient: u64,
    witness expected_remainder: u64,
) -> u64 {
    verification
        require left / right == expected_quotient
        require left % right == expected_remainder
        return 0
}
"#;

const U128_BITWISE_SHIFT_ENTRY: &str = r#"
module entry_witness_u128_bitwise_shift

action verify(
    witness value: u128,
    witness other: u128,
    witness count: u64,
    witness expected_and: u128,
    witness expected_or: u128,
    witness expected_xor: u128,
    witness expected_left: u128,
    witness expected_right: u128,
) -> u64 {
    verification
        require (value & other) == expected_and
        require (value | other) == expected_or
        require (value ^ other) == expected_xor
        require (value << count) == expected_left
        require (value >> count) == expected_right
        return 0
}
"#;

const U128_DYNAMIC_SCHEMA_BITWISE_ENTRY: &str = r#"
module entry_witness_u128_dynamic_schema_bitwise

struct Entry {
    amount: u128,
    note: Vec<u8>,
}

action verify(
    witness left: Entry,
    witness right: Entry,
    witness count: u64,
    witness expected_and: u128,
    witness expected_shl: u128,
    witness expected_add: u128,
) -> u64 {
    verification
        require (left.amount & right.amount) == expected_and
        require (left.amount << count) == expected_shl
        require (left.amount + right.amount) == expected_add
        return 0
}
"#;

const U128_DYNAMIC_SCHEMA_ENTRY: &str = r#"
module entry_witness_u128_dynamic_schema

struct Entry {
    amount: u128,
    note: Vec<u8>,
}

action verify(witness left: Entry, witness right: Entry, witness expected_add: u128) -> u64 {
    verification
        require left.amount + right.amount == expected_add
        return 0
}
"#;

const SCALAR_SHIFT_ENTRY: &str = r#"
module entry_witness_scalar_shift

action verify(
    witness unsigned: u32,
    witness signed: i32,
    witness count: u64,
    witness expected_left: u32,
    witness expected_right: u32,
    witness expected_signed_right: i32,
) -> u64 {
    verification
        require (unsigned << count) == expected_left
        require (unsigned >> count) == expected_right
        require (signed >> count) == expected_signed_right
        return 0
}
"#;

const U128_U64_ADD_ENTRY: &str = r#"
module entry_witness_u128_u64_add

action verify_add(witness wide: u128, witness delta: u64, witness expected: u128) -> u64 {
    verification
        require wide + delta == expected
        return 0
}
"#;

const GENERIC_VALUE_ENTRY: &str = r#"
module entry_witness_generic_values

struct Pair<T: fixed_value> {
    left: T,
    right: T,
}

fn first<T: fixed_value>(pair: Pair<T>) -> T {
    return pair.left
}

action verify(witness expected: u64) -> u64 {
    verification
        let pair: Pair<u64> = Pair<u64> { left: expected, right: 0 }
        let optional: Option<u64> = Option::Some<u64>(first<u64>(pair))
        let actual: u64 = match optional {
            Option::Some(value) => { value }
            Option::None => { 0 }
        }
        require actual == expected
        return 0
}
"#;

const COMPLETE_PATTERN_ENTRY: &str = r#"
module entry_witness_complete_patterns

struct Point { x: u64, y: u64 }
enum Inner { None, Some((u64, u64)) }
enum Outer { Empty, Wrapped(Inner) }
enum Switch { Off, On, Unknown }

action verify() -> u64 {
    verification
        let point: Point = Point { x: 1, y: 2 }
        let point_sum = match point { Point { x, y } => { x + y } }
        let inner: Inner = Inner::Some((20, 22))
        let outer: Outer = Outer::Wrapped(inner)
        let payload_sum = match outer {
            Outer::Wrapped(Inner::Some((left, right))) => { left + right }
            _ => { 0 }
        }
        let switch: Switch = Switch::Unknown
        let switched = match switch {
            Switch::On | Switch::Unknown => { 1 }
            Switch::Off => { 0 }
        }
        require point_sum + payload_sum + switched == 46
        return 0
}
"#;

const U128_U64_SUB_ENTRY: &str = r#"
module entry_witness_u128_u64_sub

action verify_sub(witness wide: u128, witness delta: u64, witness expected: u128) -> u64 {
    verification
        require wide - delta == expected
        return 0
}
"#;

const SIGNED_TX_MAX_CYCLES: u64 = 70_000_000;

fn canonical_multisig_v2_witness(entry_payload: Bytes) -> packed::WitnessArgs {
    let signer_a = H160::from_slice(&[0x11; 20]).expect("20-byte signer hash");
    let signer_b = H160::from_slice(&[0x22; 20]).expect("20-byte signer hash");
    let config =
        MultisigConfig::new_with(MultisigScript::V2, vec![signer_a, signer_b], 0, 2).expect("canonical 2-of-2 multisig-v2 config");

    place_entry_witness_payload_before_signing(
        &config.placeholder_witness(),
        EntryWitnessPlacementAbi::WitnessArgsInputTypeV2,
        entry_payload,
    )
    .expect("place CellScript payload before signing")
}

fn signer_id(secret_key: &SecretKey) -> H160 {
    let public_key = PublicKey::from_secret_key(&SECP256K1, secret_key);
    H160::from_slice(&blake2b_256(public_key.serialize())[..20]).expect("20-byte signer hash")
}

fn raw_entry_payload(value: u64) -> Bytes {
    let mut payload = b"CSARGv1\0".to_vec();
    payload.extend_from_slice(&value.to_le_bytes());
    Bytes::from(payload)
}

fn raw_u128_div_rem_payload(left: u128, right: u128, expected_quotient: u128, expected_remainder: u128) -> Bytes {
    let mut payload = b"CSARGv1\0".to_vec();
    payload.extend_from_slice(&left.to_le_bytes());
    payload.extend_from_slice(&right.to_le_bytes());
    payload.extend_from_slice(&expected_quotient.to_le_bytes());
    payload.extend_from_slice(&expected_remainder.to_le_bytes());
    Bytes::from(payload)
}

fn execute_u128_div_rem(
    elf: &[u8],
    left: u128,
    right: u128,
    expected_quotient: u128,
    expected_remainder: u128,
) -> ckb_script_runner::CkbScriptExecutionResult {
    let witness = canonical_multisig_v2_witness(raw_u128_div_rem_payload(left, right, expected_quotient, expected_remainder));
    let mut fixture = build_simple_fixture(Bytes::default(), 1, 1);
    fixture.witnesses = vec![witness.as_bytes()];
    execute_cellscript_script(elf, &fixture)
}

fn execute_scalar_div_rem(
    elf: &[u8],
    left: u64,
    right: u64,
    expected_quotient: u64,
    expected_remainder: u64,
) -> ckb_script_runner::CkbScriptExecutionResult {
    let mut payload = b"CSARGv1\0".to_vec();
    for value in [left, right, expected_quotient, expected_remainder] {
        payload.extend_from_slice(&value.to_le_bytes());
    }
    let witness = canonical_multisig_v2_witness(Bytes::from(payload));
    let mut fixture = build_simple_fixture(Bytes::default(), 1, 1);
    fixture.witnesses = vec![witness.as_bytes()];
    execute_cellscript_script(elf, &fixture)
}

fn raw_u128_bitwise_shift_payload(value: u128, other: u128, count: u64, expected: [u128; 5]) -> Bytes {
    let mut payload = b"CSARGv1\0".to_vec();
    payload.extend_from_slice(&value.to_le_bytes());
    payload.extend_from_slice(&other.to_le_bytes());
    payload.extend_from_slice(&count.to_le_bytes());
    for item in expected {
        payload.extend_from_slice(&item.to_le_bytes());
    }
    Bytes::from(payload)
}

fn execute_u128_bitwise_shift(
    elf: &[u8],
    value: u128,
    other: u128,
    count: u64,
    expected: [u128; 5],
) -> ckb_script_runner::CkbScriptExecutionResult {
    let witness = canonical_multisig_v2_witness(raw_u128_bitwise_shift_payload(value, other, count, expected));
    let mut fixture = build_simple_fixture(Bytes::default(), 1, 1);
    fixture.witnesses = vec![witness.as_bytes()];
    execute_cellscript_script(elf, &fixture)
}

fn execute_scalar_shift(
    elf: &[u8],
    unsigned: u32,
    signed: i32,
    count: u64,
    expected_left: u32,
    expected_right: u32,
    expected_signed_right: i32,
) -> ckb_script_runner::CkbScriptExecutionResult {
    let mut payload = b"CSARGv1\0".to_vec();
    payload.extend_from_slice(&unsigned.to_le_bytes());
    payload.extend_from_slice(&signed.to_le_bytes());
    payload.extend_from_slice(&count.to_le_bytes());
    payload.extend_from_slice(&expected_left.to_le_bytes());
    payload.extend_from_slice(&expected_right.to_le_bytes());
    payload.extend_from_slice(&expected_signed_right.to_le_bytes());
    let witness = canonical_multisig_v2_witness(Bytes::from(payload));
    let mut fixture = build_simple_fixture(Bytes::default(), 1, 1);
    fixture.witnesses = vec![witness.as_bytes()];
    execute_cellscript_script(elf, &fixture)
}

/// Encode a dynamic-layout `Entry` as the Molecule table shape the runtime
/// decodes: `<u32 total><u32 offset amount><u32 offset note><amount><note>`.
/// The dynamic `Vec<u8>` field forces table decoding for every field access,
/// including the `u128` limb loads of `amount`.
fn molecule_dynamic_entry_bytes(amount: u128, note: &[u8], total_override: Option<u32>) -> Vec<u8> {
    let amount_offset = 4 + 4 * 2;
    let note_offset = amount_offset + 16;
    let total = note_offset + note.len();
    let mut bytes = Vec::with_capacity(total);
    bytes.extend_from_slice(&total_override.unwrap_or(total as u32).to_le_bytes());
    bytes.extend_from_slice(&(amount_offset as u32).to_le_bytes());
    bytes.extend_from_slice(&(note_offset as u32).to_le_bytes());
    bytes.extend_from_slice(&amount.to_le_bytes());
    bytes.extend_from_slice(note);
    bytes
}

#[allow(clippy::too_many_arguments)]
fn execute_u128_dynamic_schema_bitwise(
    elf: &[u8],
    left: u128,
    right: u128,
    count: u64,
    expected_and: u128,
    expected_shl: u128,
    expected_add: u128,
    total_override: Option<u32>,
) -> ckb_script_runner::CkbScriptExecutionResult {
    let mut payload = b"CSARGv1\0".to_vec();
    for value in [left, right] {
        let entry = molecule_dynamic_entry_bytes(value, b"audit", total_override);
        payload.extend_from_slice(&(entry.len() as u32).to_le_bytes());
        payload.extend_from_slice(&entry);
    }
    payload.extend_from_slice(&count.to_le_bytes());
    payload.extend_from_slice(&expected_and.to_le_bytes());
    payload.extend_from_slice(&expected_shl.to_le_bytes());
    payload.extend_from_slice(&expected_add.to_le_bytes());
    let witness = canonical_multisig_v2_witness(Bytes::from(payload));
    let mut fixture = build_simple_fixture(Bytes::default(), 1, 1);
    fixture.witnesses = vec![witness.as_bytes()];
    execute_cellscript_script(elf, &fixture)
}

fn execute_u128_dynamic_schema_add(
    elf: &[u8],
    left: u128,
    right: u128,
    expected_add: u128,
    total_override: Option<u32>,
) -> ckb_script_runner::CkbScriptExecutionResult {
    let mut payload = b"CSARGv1\0".to_vec();
    for value in [left, right] {
        let entry = molecule_dynamic_entry_bytes(value, b"audit", total_override);
        payload.extend_from_slice(&(entry.len() as u32).to_le_bytes());
        payload.extend_from_slice(&entry);
    }
    payload.extend_from_slice(&expected_add.to_le_bytes());
    let witness = canonical_multisig_v2_witness(Bytes::from(payload));
    let mut fixture = build_simple_fixture(Bytes::default(), 1, 1);
    fixture.witnesses = vec![witness.as_bytes()];
    execute_cellscript_script(elf, &fixture)
}

fn execute_u128_u64_arithmetic(elf: &[u8], wide: u128, delta: u64, expected: u128) -> ckb_script_runner::CkbScriptExecutionResult {
    let mut payload = b"CSARGv1\0".to_vec();
    payload.extend_from_slice(&wide.to_le_bytes());
    payload.extend_from_slice(&delta.to_le_bytes());
    payload.extend_from_slice(&expected.to_le_bytes());
    let witness = canonical_multisig_v2_witness(Bytes::from(payload));
    let mut fixture = build_simple_fixture(Bytes::default(), 1, 1);
    fixture.witnesses = vec![witness.as_bytes()];
    execute_cellscript_script(elf, &fixture)
}

fn execute_on_second_group_input(witness: Bytes) -> ckb_script_runner::CkbScriptExecutionResult {
    let elf = compile_cellscript_source_to_elf(PARAMETERIZED_ENTRY, "verify", None);
    let mut fixture = build_simple_fixture(Bytes::default(), 2, 1);
    fixture.current_type_script_input_indices = vec![1];
    fixture.witnesses = vec![Bytes::from_static(b"unrelated-global-input-zero"), witness];
    execute_cellscript_script(&elf, &fixture)
}

fn execute_on_output_only_group(witness: Bytes) -> ckb_script_runner::CkbScriptExecutionResult {
    let elf = compile_cellscript_source_to_elf(PARAMETERIZED_ENTRY, "verify", None);
    let mut fixture = build_simple_fixture(Bytes::default(), 1, 1);
    fixture.current_type_script_input_indices.clear();
    fixture.witnesses = vec![witness];
    execute_cellscript_script(&elf, &fixture)
}

fn execute_bounded_consume(amounts: &[u64], malformed_data: Option<Bytes>) -> ckb_script_runner::CkbScriptExecutionResult {
    let elf = compile_cellscript_source_to_elf(BOUNDED_CONSUME_RUNTIME_ENTRY, "verify", None);
    let input_count = amounts.len().max(1);
    let mut fixture = build_simple_fixture(Bytes::default(), input_count, 1);
    fixture.current_type_script_input_indices = (0..amounts.len()).collect();
    for (index, amount) in amounts.iter().enumerate() {
        fixture.inputs[index].data = Bytes::copy_from_slice(&amount.to_le_bytes());
    }
    if let Some(data) = malformed_data {
        fixture.inputs[0].data = data;
    }
    execute_cellscript_script(&elf, &fixture)
}

fn bounded_create_plan_payload(amounts: &[u64], owner: [u8; 32]) -> Bytes {
    let elements = amounts
        .iter()
        .map(|amount| {
            let mut element = owner.to_vec();
            element.extend_from_slice(&amount.to_le_bytes());
            element
        })
        .collect::<Vec<_>>();
    let plan = cellscript::encode_bounded_output_plan_v1(&elements, 40, 2).expect("encode bounded output plan");
    let mut payload = b"CSARGv1\0".to_vec();
    payload.extend_from_slice(&(plan.len() as u32).to_le_bytes());
    payload.extend_from_slice(&plan);
    Bytes::from(payload)
}

fn execute_bounded_create(
    amounts: &[u64],
    output_amounts: &[u64],
    output_capacity: u64,
    owner: [u8; 32],
) -> ckb_script_runner::CkbScriptExecutionResult {
    let payload = bounded_create_plan_payload(amounts, owner);
    execute_bounded_create_payload(payload, output_amounts, output_capacity)
}

fn execute_bounded_create_payload(
    payload: Bytes,
    output_amounts: &[u64],
    output_capacity: u64,
) -> ckb_script_runner::CkbScriptExecutionResult {
    let elf = compile_cellscript_source_to_elf(BOUNDED_CREATE_RUNTIME_ENTRY, "verify", None);
    let witness = canonical_multisig_v2_witness(payload);
    let mut fixture = build_simple_fixture(Bytes::default(), 1, output_amounts.len());
    fixture.current_type_script_input_indices = if output_amounts.is_empty() { vec![0] } else { Vec::new() };
    fixture.witnesses = vec![witness.as_bytes()];
    for (output, amount) in fixture.outputs.iter_mut().zip(output_amounts) {
        output.capacity = output_capacity;
        output.data = Bytes::copy_from_slice(&amount.to_le_bytes());
    }
    execute_cellscript_script(&elf, &fixture)
}

fn bounded_batch_payload(elements: &[Vec<u8>], element_width: usize, max_elements: usize) -> Bytes {
    let plan = cellscript::encode_bounded_output_plan_v1(elements, element_width, max_elements).expect("encode example plan");
    let mut payload = b"CSARGv1\0".to_vec();
    payload.extend_from_slice(&(plan.len() as u32).to_le_bytes());
    payload.extend_from_slice(&plan);
    Bytes::from(payload)
}

fn execute_bounded_batch_example(
    elf: &[u8],
    input_data: &[Vec<u8>],
    plan_elements: &[Vec<u8>],
    plan_width: usize,
    max_plan_elements: usize,
    output_data: &[Vec<u8>],
) -> ckb_script_runner::CkbScriptExecutionResult {
    let witness = canonical_multisig_v2_witness(bounded_batch_payload(plan_elements, plan_width, max_plan_elements));
    let mut fixture = build_simple_fixture(Bytes::default(), input_data.len(), output_data.len());
    fixture.current_type_script_input_indices = (0..input_data.len()).collect();
    fixture.witnesses =
        std::iter::once(witness.as_bytes()).chain(std::iter::repeat_n(Bytes::default(), input_data.len().saturating_sub(1))).collect();
    for (cell, data) in fixture.inputs.iter_mut().zip(input_data) {
        cell.data = Bytes::copy_from_slice(data);
    }
    for (cell, data) in fixture.outputs.iter_mut().zip(output_data) {
        cell.data = Bytes::copy_from_slice(data);
    }
    execute_cellscript_script(elf, &fixture)
}

fn address_and_u64(owner: [u8; 32], value: u64) -> Vec<u8> {
    let mut bytes = owner.to_vec();
    bytes.extend_from_slice(&value.to_le_bytes());
    bytes
}

fn u64_pair(first: u64, second: u64) -> Vec<u8> {
    let mut bytes = first.to_le_bytes().to_vec();
    bytes.extend_from_slice(&second.to_le_bytes());
    bytes
}

#[test]
fn signed_multisig_v2_lock_and_cellscript_type_execute_in_ckb_vm() -> Result<(), ScriptSignError> {
    let key_a = SecretKey::from_slice(&[0x11; 32]).expect("valid signer A key");
    let key_b = SecretKey::from_slice(&[0x22; 32]).expect("valid signer B key");
    let config = MultisigConfig::new_with(MultisigScript::V2, vec![signer_id(&key_a), signer_id(&key_b)], 0, 2)?;

    let mut context = Context::new_with_deterministic_rng();
    let multisig_v2 = ckb_system_scripts_v0_6_0::BUNDLED_CELL
        .get("specs/cells/secp256k1_blake160_multisig_all")
        .expect("bundled multisig-v2 script");
    context.deploy_cell(Bytes::copy_from_slice(&multisig_v2));
    let secp256k1_data = ckb_system_scripts_v0_6_0::BUNDLED_CELL.get("specs/cells/secp256k1_data").expect("bundled secp256k1 data");
    let secp256k1_data_out_point = context.deploy_cell(Bytes::copy_from_slice(&secp256k1_data));

    let always_success_elf = compile_cellscript_source_to_elf(ALWAYS_SUCCESS_LOCK, "always_success", None);
    let always_success_out_point = context.deploy_cell(Bytes::from(always_success_elf));
    let always_success_lock = context.build_script(&always_success_out_point, Bytes::default()).expect("build always-success lock");

    let cellscript_elf = compile_cellscript_source_to_elf(PARAMETERIZED_ENTRY, "verify", None);
    let cellscript_out_point = context.deploy_cell(Bytes::from(cellscript_elf));
    let cellscript_type = context.build_script(&cellscript_out_point, Bytes::default()).expect("build CellScript type script");
    let multisig_lock: packed::Script = (&config).into();

    let unrelated_input = context.create_cell(
        packed::CellOutput::new_builder()
            .capacity::<packed::Uint64>(100_000_000_000u64.pack())
            .lock(always_success_lock.clone())
            .build(),
        Bytes::default(),
    );
    let multisig_input = context.create_cell(
        packed::CellOutput::new_builder()
            .capacity::<packed::Uint64>(100_000_000_000u64.pack())
            .lock(multisig_lock.clone())
            .type_(Some(cellscript_type.clone()).pack())
            .build(),
        Bytes::default(),
    );
    let output = packed::CellOutput::new_builder()
        .capacity::<packed::Uint64>(190_000_000_000u64.pack())
        .lock(always_success_lock)
        .type_(Some(cellscript_type).pack())
        .build();

    let unsigned_witness = place_entry_witness_payload_before_signing(
        &config.placeholder_witness(),
        EntryWitnessPlacementAbi::WitnessArgsInputTypeV2,
        raw_entry_payload(42),
    )
    .expect("place entry payload before signing");
    let tx = TransactionBuilder::default()
        .inputs([
            packed::CellInput::new_builder().previous_output(unrelated_input).build(),
            packed::CellInput::new_builder().previous_output(multisig_input).build(),
        ])
        .output(output)
        .output_data(Bytes::default().pack())
        .cell_dep(packed::CellDep::new_builder().out_point(secp256k1_data_out_point).dep_type(DepType::Code).build())
        .witnesses([Bytes::from_static(b"unrelated-global-input-zero"), unsigned_witness.as_bytes()].pack())
        .build();
    let tx = context.complete_tx(tx);

    let raw_signer = SecpCkbRawKeySigner::new_with_secret_keys(vec![key_a, key_b]);
    let signer = SecpMultisigScriptSigner::new(Box::new(raw_signer), config);
    let mut lock_group = ScriptGroup::from_lock_script(&multisig_lock);
    lock_group.input_indices.push(1);
    let signed_tx = signer.sign_tx(&tx, &lock_group)?;

    let signed_witness = packed::WitnessArgs::from_slice(signed_tx.witnesses().get(1).expect("multisig witness").raw_data().as_ref())
        .expect("signed WitnessArgs");
    let lock = signed_witness.lock().to_opt().expect("signed multisig lock").raw_data();
    let signature_offset = 4 + 2 * 20;
    assert_eq!(&lock[..4], &[0, 0, 2, 2], "canonical 2-of-2 multisig header");
    assert!(lock[signature_offset..].iter().any(|byte| *byte != 0), "multisig signatures must be populated");
    context.verify_tx(&signed_tx, SIGNED_TX_MAX_CYCLES).expect("multisig-v2 lock and CellScript type script must both pass");

    // A valid, otherwise unused output_type mutation keeps the CellScript
    // input_type payload valid, but must invalidate the multisig signature.
    let tampered_witness = signed_witness.as_builder().output_type(Some(Bytes::from_static(b"post-signing-mutation")).pack()).build();
    let mut witnesses: Vec<packed::Bytes> = signed_tx.witnesses().into_iter().collect();
    witnesses[1] = tampered_witness.as_bytes().pack();
    let tampered_tx = signed_tx.as_advanced_builder().set_witnesses(witnesses).build();
    assert!(
        context.verify_tx(&tampered_tx, SIGNED_TX_MAX_CYCLES).is_err(),
        "mutating WitnessArgs after signing must invalidate multisig-v2"
    );

    Ok(())
}

#[test]
fn raw_v1_group_input_payload_is_rejected_by_placement_abi_v2() {
    let result = execute_on_second_group_input(raw_entry_payload(42));
    assert_eq!(
        result.exit_code, 25,
        "placement ABI v2 must require WitnessArgs.input_type instead of accepting a raw payload alias: {:?}",
        result.captured_debug
    );
}

#[test]
fn witnessargs_input_type_falls_back_to_group_output_zero() {
    let witness = canonical_multisig_v2_witness(raw_entry_payload(42));
    let result = execute_on_output_only_group(witness.as_bytes());
    assert_eq!(result.exit_code, 0, "an output-only type group must resolve GroupOutput#0: {:?}", result.captured_debug);
}

#[test]
fn missing_input_group_witness_must_not_fall_back_to_an_output_witness() {
    let elf = compile_cellscript_source_to_elf(PARAMETERIZED_ENTRY, "verify", None);
    let mut fixture = build_simple_fixture(Bytes::default(), 2, 1);
    fixture.current_type_script_input_indices = vec![1];
    // The active input group exists at transaction input 1, but its witness
    // does not. GroupOutput#0 can resolve this unrelated, valid witness at 0.
    fixture.witnesses = vec![canonical_multisig_v2_witness(raw_entry_payload(42)).as_bytes()];
    let result = execute_cellscript_script(&elf, &fixture);
    assert_eq!(result.exit_code, 25, "an existing input group must never use output fallback: {:?}", result.captured_debug);
}

#[test]
fn u128_division_and_modulo_execute_exact_wide_values_in_ckb_vm() {
    let elf = compile_cellscript_source_to_elf(U128_DIV_REM_ENTRY, "verify", None);
    let vectors = [(0, 1), (u64::MAX as u128 + 17, 97), (1u128 << 127, 3), (u128::MAX, (1u128 << 127) + 123), (u128::MAX, u128::MAX)];

    for (left, right) in vectors {
        let expected_quotient = left / right;
        let expected_remainder = left % right;
        let result = execute_u128_div_rem(&elf, left, right, expected_quotient, expected_remainder);
        assert_eq!(
            result.exit_code, 0,
            "{left} / {right} should equal {expected_quotient} with remainder {expected_remainder} in CKB-VM: {:?}",
            result.captured_debug
        );
    }

    let zero = execute_u128_div_rem(&elf, u128::MAX, 0, 0, 0);
    assert_eq!(zero.exit_code, 20, "u128 division or modulo by zero must use the stable numeric failure: {:?}", zero.captured_debug);
}

#[test]
fn scalar_division_and_modulo_reject_zero_in_ckb_vm() {
    let elf = compile_cellscript_source_to_elf(SCALAR_DIV_REM_ENTRY, "verify", None);
    let valid = execute_scalar_div_rem(&elf, u64::MAX, 97, u64::MAX / 97, u64::MAX % 97);
    assert_eq!(valid.exit_code, 0, "scalar division and modulo must execute exactly: {:?}", valid.captured_debug);

    let zero = execute_scalar_div_rem(&elf, u64::MAX, 0, 0, 0);
    assert_eq!(zero.exit_code, 20, "scalar division or modulo by zero must use the stable numeric failure: {:?}", zero.captured_debug);
}

#[test]
fn u128_bitwise_and_shift_operations_execute_in_ckb_vm() {
    let elf = compile_cellscript_source_to_elf(U128_BITWISE_SHIFT_ENTRY, "verify", None);
    let vectors = [
        (u128::MAX, 0x55aa_55aa_55aa_55aa_aa55_aa55_aa55_aa55, 0),
        (0x0123_4567_89ab_cdef_fedc_ba98_7654_3210, 0xf0f0_0f0f_f0f0_0f0f_aaaa_5555_aaaa_5555, 1),
        (1, u128::MAX - 1, 63),
        (1, u128::MAX - 1, 64),
        (0x8000_0000_0000_0001_0000_0000_0000_0001, u128::MAX, 127),
    ];
    for (value, other, count) in vectors {
        let expected = [value & other, value | other, value ^ other, value << count, value >> count];
        let result = execute_u128_bitwise_shift(&elf, value, other, count, expected);
        assert_eq!(
            result.exit_code, 0,
            "u128 bitwise/shift vector count={count} must execute exactly in CKB-VM: {:?}",
            result.captured_debug
        );
    }

    let invalid = execute_u128_bitwise_shift(&elf, 1, 0, 128, [0, 1, 1, 0, 0]);
    assert_eq!(
        invalid.exit_code, 65,
        "runtime shift amount equal to the value width must use shift-amount-invalid: {:?}",
        invalid.captured_debug
    );
}

#[test]
fn u128_bitwise_add_and_shift_on_dynamic_schema_fields_execute_in_ckb_vm() {
    let elf = compile_cellscript_source_to_elf(U128_DYNAMIC_SCHEMA_BITWISE_ENTRY, "verify", None);
    let vectors: [(u128, u128, u64); 3] = [
        (0x00ff_ffee_ddcc_bbaa_55aa_55aa_55aa_55aa, 0x55aa_55aa_55aa_55aa_aa55_aa55_aa55_aa55, 3),
        (0x0123_4567_89ab_cdef_fedc_ba98_7654_3210, 0xf0f0_0f0f_f0f0_0f0f_aaaa_5555_aaaa_5555, 67),
        (1, u128::MAX - 1, 127),
    ];
    for (left, right, count) in vectors {
        let expected_add = left.checked_add(right).expect("vector must not overflow");
        let result = execute_u128_dynamic_schema_bitwise(&elf, left, right, count, left & right, left << count, expected_add, None);
        assert_eq!(
            result.exit_code, 0,
            "u128 bitwise/add/shift over Molecule-table-decoded fields (count={count}) must execute exactly in CKB-VM: {:?}",
            result.captured_debug
        );
    }

    let wrong_and = execute_u128_dynamic_schema_bitwise(
        &elf,
        0xff00_ff00_ff00_ff00_ff00_ff00_ff00_ff00,
        1,
        3,
        1,
        0,
        0xff01_ff00_ff00_ff00_ff00_ff00_ff00_ff00,
        None,
    );
    assert_eq!(
        wrong_and.exit_code, 5,
        "a wrong expected bitwise result over dynamic schema fields must use assertion-failed: {:?}",
        wrong_and.captured_debug
    );

    let invalid_shift = execute_u128_dynamic_schema_bitwise(&elf, 1, 1, 128, 1, 0, 2, None);
    assert_eq!(
        invalid_shift.exit_code, 65,
        "a dynamic schema field shift amount of 128 must use shift-amount-invalid: {:?}",
        invalid_shift.captured_debug
    );

    let bad_total = execute_u128_dynamic_schema_bitwise(&elf, 8, 1, 3, 0, 64, 9, Some(255));
    assert_eq!(
        bad_total.exit_code, 2,
        "a Molecule table total length that disagrees with the payload length must use bounds-check-failed: {:?}",
        bad_total.captured_debug
    );
}

#[test]
fn scalar_shift_width_and_i32_signedness_execute_in_ckb_vm() {
    let elf = compile_cellscript_source_to_elf(SCALAR_SHIFT_ENTRY, "verify", None);
    let result = execute_scalar_shift(&elf, 0xf000_000f, -16, 4, 0x0000_00f0, 0x0f00_0000, -1);
    assert_eq!(result.exit_code, 0, "u32 truncation and i32 arithmetic shift must match source widths: {:?}", result.captured_debug);

    let invalid = execute_scalar_shift(&elf, 1, -1, 32, 0, 0, 0);
    assert_eq!(
        invalid.exit_code, 65,
        "runtime shift amount equal to the u32 width must use shift-amount-invalid: {:?}",
        invalid.captured_debug
    );
}

#[test]
fn generic_struct_function_and_option_execute_in_ckb_vm() {
    let elf = compile_cellscript_source_to_elf(GENERIC_VALUE_ENTRY, "verify", None);
    let witness = canonical_multisig_v2_witness(raw_entry_payload(42));
    let mut fixture = build_simple_fixture(Bytes::default(), 1, 1);
    fixture.witnesses = vec![witness.as_bytes()];
    let result = execute_cellscript_script(&elf, &fixture);
    assert_eq!(result.exit_code, 0, "generic value kernel must execute in CKB-VM: {:?}", result.captured_debug);
}

#[test]
fn complete_value_patterns_execute_in_ckb_vm() {
    let elf = compile_cellscript_source_to_elf(COMPLETE_PATTERN_ENTRY, "verify", None);
    let fixture = build_simple_fixture(Bytes::default(), 1, 1);
    let result = execute_cellscript_script(&elf, &fixture);
    assert_eq!(result.exit_code, 0, "nested/struct/tuple/or patterns must execute in CKB-VM: {:?}", result.captured_debug);
}

#[test]
fn labeled_break_and_continue_execute_in_ckb_vm() {
    let elf = compile_cellscript_source_to_elf(LOOP_CONTROL_ENTRY, "verify", None);
    let fixture = build_simple_fixture(Bytes::default(), 1, 1);
    let result = execute_cellscript_script(&elf, &fixture);
    assert_eq!(result.exit_code, 0, "labeled break and continue must execute in CKB-VM: {:?}", result.captured_debug);
}

#[test]
fn bounded_collection_entries_fail_closed_with_stable_runtime_code_in_ckb_vm() {
    for (operation, source) in
        [("consume_each", BOUNDED_COLLECTION_FAIL_CLOSED_ENTRY), ("create_each", BOUNDED_CREATE_FAIL_CLOSED_ENTRY)]
    {
        let elf = compile_cellscript_source_to_elf(source, "verify", None);
        let fixture = build_simple_fixture(Bytes::default(), 1, 1);
        let result = execute_cellscript_script(&elf, &fixture);
        assert_eq!(
            result.exit_code, 24,
            "{operation} entry must reject before witness decoding instead of returning success: {:?}",
            result.captured_debug
        );
    }
}

#[test]
fn bounded_consume_scans_the_exact_type_group_with_runtime_cardinality_in_ckb_vm() {
    for amounts in [&[][..], &[1][..], &[1, 2][..]] {
        let result = execute_bounded_consume(amounts, None);
        assert_eq!(result.exit_code, 0, "0..=N canonical GroupInput cells must pass: {amounts:?}: {:?}", result.captured_debug);
    }

    let too_many = execute_bounded_consume(&[1, 2, 3], None);
    assert_eq!(too_many.exit_code, 21, "a successful GroupInput load at index N must reject N+1 cells: {:?}", too_many.captured_debug);
}

#[test]
fn bounded_consume_rejects_bad_element_data_and_predicates_in_ckb_vm() {
    let malformed = execute_bounded_consume(&[1], Some(Bytes::from_static(&[1, 0, 0, 0])));
    assert_eq!(malformed.exit_code, 4, "fixed-width decode must be exact: {:?}", malformed.captured_debug);

    let predicate_failure = execute_bounded_consume(&[1, 0], None);
    assert_eq!(
        predicate_failure.exit_code, 5,
        "the predicate must execute for every decoded group element: {:?}",
        predicate_failure.captured_debug
    );
}

#[test]
fn bounded_create_binds_the_versioned_plan_to_canonical_group_outputs_in_ckb_vm() {
    let owner = deterministic_always_success_lock_hash();
    for amounts in [&[][..], &[1][..], &[1, 2][..]] {
        let result = execute_bounded_create(amounts, amounts, 100_000_000_000, owner);
        assert_eq!(result.exit_code, 0, "plan and GroupOutput views must correspond exactly: {:?}", result.captured_debug);
    }

    let missing = execute_bounded_create(&[1, 2], &[1], 100_000_000_000, owner);
    assert_eq!(missing.exit_code, 21, "missing GroupOutput must be a count mismatch: {:?}", missing.captured_debug);

    let extra = execute_bounded_create(&[1], &[1, 2], 100_000_000_000, owner);
    assert_eq!(extra.exit_code, 21, "extra GroupOutput must be a count mismatch: {:?}", extra.captured_debug);
}

#[test]
fn bounded_create_rejects_output_data_lock_capacity_and_predicate_mismatches_in_ckb_vm() {
    let owner = deterministic_always_success_lock_hash();
    let bad_data = execute_bounded_create(&[1], &[2], 100_000_000_000, owner);
    assert_eq!(bad_data.exit_code, 3, "output data mismatch must fail closed: {:?}", bad_data.captured_debug);

    let bad_lock = execute_bounded_create(&[1], &[1], 100_000_000_000, [0; 32]);
    assert_eq!(bad_lock.exit_code, 12, "output lock mismatch must use the stable lock code: {:?}", bad_lock.captured_debug);

    let low_capacity = execute_bounded_create(&[1], &[1], 9_999_999_999, owner);
    assert_eq!(
        low_capacity.exit_code, 26,
        "declared output capacity floor must be checked on chain: {:?}",
        low_capacity.captured_debug
    );

    let predicate = execute_bounded_create(&[0], &[0], 100_000_000_000, owner);
    assert_eq!(predicate.exit_code, 5, "plan predicate must execute exactly once per element: {:?}", predicate.captured_debug);
}

#[test]
fn bounded_create_rejects_noncanonical_or_over_bound_plan_codecs_in_ckb_vm() {
    let owner = deterministic_always_success_lock_hash();
    let mut bad_magic = bounded_create_plan_payload(&[1], owner).to_vec();
    bad_magic[12] ^= 1;
    let result = execute_bounded_create_payload(Bytes::from(bad_magic), &[1], 100_000_000_000);
    assert_eq!(result.exit_code, 25, "plan version/magic mismatch must use the entry ABI code: {:?}", result.captured_debug);

    let mut over_bound_inner = b"CSBPLv1\0".to_vec();
    over_bound_inner.extend_from_slice(&3_u32.to_le_bytes());
    for amount in [1_u64, 2, 3] {
        over_bound_inner.extend_from_slice(&owner);
        over_bound_inner.extend_from_slice(&amount.to_le_bytes());
    }
    let mut over_bound = b"CSARGv1\0".to_vec();
    over_bound.extend_from_slice(&(over_bound_inner.len() as u32).to_le_bytes());
    over_bound.extend_from_slice(&over_bound_inner);
    let result = execute_bounded_create_payload(Bytes::from(over_bound), &[1, 2], 100_000_000_000);
    assert_eq!(result.exit_code, 21, "plan count above N must use the collection bound code: {:?}", result.captured_debug);

    let mut trailing_inner = cellscript::encode_bounded_output_plan_v1(
        &[{
            let mut element = owner.to_vec();
            element.extend_from_slice(&1_u64.to_le_bytes());
            element
        }],
        40,
        2,
    )
    .unwrap();
    trailing_inner.push(0);
    let mut trailing = b"CSARGv1\0".to_vec();
    trailing.extend_from_slice(&(trailing_inner.len() as u32).to_le_bytes());
    trailing.extend_from_slice(&trailing_inner);
    let result = execute_bounded_create_payload(Bytes::from(trailing), &[1], 100_000_000_000);
    assert_eq!(result.exit_code, 25, "trailing plan bytes must be rejected: {:?}", result.captured_debug);
}

#[test]
fn dynamic_batch_examples_execute_and_reject_scenario_specific_attacks_in_ckb_vm() {
    let owner = deterministic_always_success_lock_hash();

    let claim_elf = compile_cellscript_source_to_elf(BATCH_CLAIM_EXAMPLE, "claim_many", None);
    let claim_inputs = [address_and_u64(owner, 4), address_and_u64(owner, 6)];
    let claim_plans = [address_and_u64(owner, 4), address_and_u64(owner, 6)];
    let claim_outputs = [4_u64.to_le_bytes().to_vec(), 6_u64.to_le_bytes().to_vec()];
    let claim = execute_bounded_batch_example(&claim_elf, &claim_inputs, &claim_plans, 40, 64, &claim_outputs);
    assert_eq!(claim.exit_code, 0, "variable-cardinality claim example must execute: {:?}", claim.captured_debug);
    let wrong_claim_plans = [address_and_u64(owner, 4), address_and_u64(owner, 7)];
    let wrong_claim_outputs = [4_u64.to_le_bytes().to_vec(), 7_u64.to_le_bytes().to_vec()];
    let claim_mismatch = execute_bounded_batch_example(&claim_elf, &claim_inputs, &wrong_claim_plans, 40, 64, &wrong_claim_outputs);
    assert_eq!(claim_mismatch.exit_code, 5, "claim input/output aggregate mismatch must reject atomically");

    let order_elf = compile_cellscript_source_to_elf(ATOMIC_ORDER_SETTLEMENT_EXAMPLE, "settle_orders", None);
    let order_data = |side: u64, amount: u64| {
        let mut data = 1_u64.to_le_bytes().to_vec();
        data.extend_from_slice(&owner);
        data.extend_from_slice(&side.to_le_bytes());
        data.extend_from_slice(&amount.to_le_bytes());
        data
    };
    let settlement_plan = |amount: u64| {
        let mut data = owner.to_vec();
        data.extend_from_slice(&1_u64.to_le_bytes());
        data.extend_from_slice(&amount.to_le_bytes());
        data
    };
    let order_inputs = [order_data(0, 3), order_data(1, 5)];
    let settlement_plans = [settlement_plan(3), settlement_plan(5)];
    let settlement_outputs = [u64_pair(1, 3), u64_pair(1, 5)];
    let settlement = execute_bounded_batch_example(&order_elf, &order_inputs, &settlement_plans, 48, 16, &settlement_outputs);
    assert_eq!(settlement.exit_code, 0, "1..=16 atomic settlement example must execute: {:?}", settlement.captured_debug);
    let seventeen_orders = (0..17).map(|index| order_data(index % 2, 1)).collect::<Vec<_>>();
    let sixteen_plans = (0..16).map(|_| settlement_plan(1)).collect::<Vec<_>>();
    let sixteen_outputs = (0..16).map(|_| u64_pair(1, 1)).collect::<Vec<_>>();
    let order_overflow = execute_bounded_batch_example(&order_elf, &seventeen_orders, &sixteen_plans, 48, 16, &sixteen_outputs);
    assert_eq!(order_overflow.exit_code, 21, "the seventeenth order must fail the on-chain cardinality bound");

    let merge_elf = compile_cellscript_source_to_elf(CELL_MERGE_EXAMPLE, "merge_cells", None);
    let fragment_inputs = [4_u64.to_le_bytes().to_vec(), 6_u64.to_le_bytes().to_vec()];
    let merge_plan = [address_and_u64(owner, 10)];
    let merge_output = [10_u64.to_le_bytes().to_vec()];
    let merge = execute_bounded_batch_example(&merge_elf, &fragment_inputs, &merge_plan, 40, 1, &merge_output);
    assert_eq!(merge.exit_code, 0, "fragment merge example must execute: {:?}", merge.captured_debug);
    let wrong_merge_plan = [address_and_u64(owner, 11)];
    let wrong_merge_output = [11_u64.to_le_bytes().to_vec()];
    let merge_inflation = execute_bounded_batch_example(&merge_elf, &fragment_inputs, &wrong_merge_plan, 40, 1, &wrong_merge_output);
    assert_eq!(merge_inflation.exit_code, 5, "merge inflation must fail before accepting the output");

    let bridge_elf = compile_cellscript_source_to_elf(BRIDGE_ROLLUP_BATCH_EXAMPLE, "execute_bridge_batch", None);
    let bridge_record = |amount: u64, nonce: u64| {
        let mut data = owner.to_vec();
        data.extend_from_slice(&amount.to_le_bytes());
        data.extend_from_slice(&nonce.to_le_bytes());
        data
    };
    let bridge_inputs = [bridge_record(7, 1), bridge_record(9, 2)];
    let bridge_plans = [bridge_record(7, 1), bridge_record(9, 2)];
    let bridge_outputs = [u64_pair(7, 1), u64_pair(9, 2)];
    let bridge = execute_bounded_batch_example(&bridge_elf, &bridge_inputs, &bridge_plans, 48, 64, &bridge_outputs);
    assert_eq!(bridge.exit_code, 0, "canonical bridge/rollup batch must execute: {:?}", bridge.captured_debug);
    let replayed_inputs = [bridge_record(7, 1), bridge_record(9, 3)];
    let replay = execute_bounded_batch_example(&bridge_elf, &replayed_inputs, &bridge_plans, 48, 64, &bridge_outputs);
    assert_eq!(replay.exit_code, 5, "non-consecutive bridge nonce must reject the whole batch");
}

#[test]
fn witnessargs_output_type_is_not_an_entry_payload_alias() {
    let witness = canonical_multisig_v2_witness(raw_entry_payload(42))
        .as_builder()
        .input_type(None::<Bytes>.pack())
        .output_type(Some(raw_entry_payload(42)).pack())
        .build();
    let result = execute_on_second_group_input(witness.as_bytes());
    assert_eq!(result.exit_code, 25, "wrong WitnessArgs field must fail closed: {:?}", result.captured_debug);
}

#[test]
fn malformed_witnessargs_input_type_length_fails_closed() {
    let witness = canonical_multisig_v2_witness(raw_entry_payload(42));
    let mut encoded = witness.as_slice().to_vec();
    let input_type_offset = u32::from_le_bytes(encoded[8..12].try_into().expect("input_type table offset")) as usize;
    let declared_len =
        u32::from_le_bytes(encoded[input_type_offset..input_type_offset + 4].try_into().expect("input_type Bytes length"));
    encoded[input_type_offset..input_type_offset + 4].copy_from_slice(&(declared_len + 1).to_le_bytes());

    let result = execute_on_second_group_input(Bytes::from(encoded));
    assert_eq!(result.exit_code, 25, "malformed Molecule must fail closed: {:?}", result.captured_debug);
}

#[test]
fn malformed_unselected_witnessargs_field_still_fails_closed() {
    let witness = canonical_multisig_v2_witness(raw_entry_payload(42))
        .as_builder()
        .output_type(Some(Bytes::from_static(b"protocol-output-data")).pack())
        .build();
    let mut encoded = witness.as_slice().to_vec();
    let output_type_offset = u32::from_le_bytes(encoded[12..16].try_into().expect("output_type table offset")) as usize;
    let declared_len =
        u32::from_le_bytes(encoded[output_type_offset..output_type_offset + 4].try_into().expect("output_type Bytes length"));
    encoded[output_type_offset..output_type_offset + 4].copy_from_slice(&(declared_len + 1).to_le_bytes());

    let result = execute_on_second_group_input(Bytes::from(encoded));
    assert_eq!(result.exit_code, 25, "the placement ABI must validate the whole WitnessArgs table: {:?}", result.captured_debug);
}

#[test]
fn u128_add_on_dynamic_schema_fields_executes_exactly_in_ckb_vm() {
    let elf = compile_cellscript_source_to_elf(U128_DYNAMIC_SCHEMA_ENTRY, "verify", None);
    let vectors: [(u128, u128); 3] = [
        (0x00ff_ffee_ddcc_bbaa_55aa_55aa_55aa_55aa, 0x55aa_55aa_55aa_55aa_aa55_aa55_aa55_aa55),
        (0x0123_4567_89ab_cdef_fedc_ba98_7654_3210, 0xf0f0_0f0f_f0f0_0f0f_aaaa_5555_aaaa_5555),
        (1, u128::MAX - 1),
    ];
    for (left, right) in vectors {
        let expected_add = left.checked_add(right).expect("vector must not overflow");
        let result = execute_u128_dynamic_schema_add(&elf, left, right, expected_add, None);
        assert_eq!(
            result.exit_code, 0,
            "u128 addition over Molecule-table-decoded fields must execute exactly in CKB-VM: {:?}",
            result.captured_debug
        );
    }

    let wrong = execute_u128_dynamic_schema_add(&elf, 1, 2, 4, None);
    assert_eq!(wrong.exit_code, 5, "a wrong expected sum must fail the assertion: {:?}", wrong.captured_debug);

    let malformed = execute_u128_dynamic_schema_add(&elf, 8, 1, 9, Some(255));
    assert_eq!(
        malformed.exit_code, 2,
        "a mismatched Molecule table length must fail the bounds check: {:?}",
        malformed.captured_debug
    );
}

#[test]
fn u128_u64_arithmetic_checks_carry_overflow_and_underflow_in_ckb_vm() {
    let add_elf = compile_cellscript_source_to_elf(U128_U64_ADD_ENTRY, "verify_add", None);
    let carried = execute_u128_u64_arithmetic(&add_elf, u64::MAX as u128, 1, 1u128 << 64);
    assert_eq!(carried.exit_code, 0, "u128 + u64 carry must execute exactly: {:?}", carried.captured_debug);

    let overflow = execute_u128_u64_arithmetic(&add_elf, u128::MAX, 1, 0);
    assert_eq!(overflow.exit_code, 49, "u128 + u64 overflow must fail closed: {:?}", overflow.captured_debug);

    let sub_elf = compile_cellscript_source_to_elf(U128_U64_SUB_ENTRY, "verify_sub", None);
    let borrowed = execute_u128_u64_arithmetic(&sub_elf, 1u128 << 64, 1, u64::MAX as u128);
    assert_eq!(borrowed.exit_code, 0, "u128 - u64 borrow must execute exactly: {:?}", borrowed.captured_debug);

    let underflow = execute_u128_u64_arithmetic(&sub_elf, 0, 1, 0);
    assert_eq!(underflow.exit_code, 49, "u128 - u64 underflow must fail closed: {:?}", underflow.captured_debug);
}
