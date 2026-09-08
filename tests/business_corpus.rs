//! Canonical same-transaction CKB-VM composition anchor for the 0.30 corpus.

use cellscript::{strip_vm_abi_trailer, CompileOptions, EntryWitnessArg};
use ckb_testtool::{
    builtin::ALWAYS_SUCCESS,
    ckb_hash::blake2b_256,
    ckb_types::{
        bytes::Bytes,
        core::{Capacity, DepType, TransactionBuilder, TransactionView},
        packed,
        prelude::*,
    },
    context::Context,
};
use serde::Deserialize;

const ORDER_SOURCE: &str = include_str!("fixtures/capability_anchor_order.cell");
const TOKEN_SOURCE: &str = include_str!("fixtures/capability_anchor_token.cell");
const AUTHORIZATION_SOURCE: &str = include_str!("fixtures/capability_anchor_authorization.cell");
const POLICY_DATA: &[u8] = b"cellscript-0.30-anchor-policy";
const MAX_CYCLES: u64 = 10_000_000;

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Mutation {
    None,
    AuthorizationCredential,
    TokenAmount,
    OrderAmount,
    Dependency,
}

#[derive(Debug, Deserialize)]
struct AnchorFixture {
    schema: String,
    source_files: Vec<String>,
    policy_data_hex: String,
    artifacts: usize,
    script_groups: usize,
    positive_case: String,
    adversarial_cases: Vec<AdversarialCase>,
    measured: AnchorMeasurements,
    budgets: AnchorBudgets,
}

#[derive(Debug, Deserialize)]
struct AdversarialCase {
    name: String,
    mutation: Mutation,
}

#[derive(Debug, Deserialize)]
struct AnchorMeasurements {
    cycles: u64,
    combined_elf_bytes: usize,
    max_stack_frame_bytes: u32,
    witness_bytes: usize,
    transaction_bytes: usize,
    occupied_capacity_shannons: u64,
}

#[derive(Debug, Deserialize)]
struct AnchorBudgets {
    max_cycles: u64,
    max_combined_elf_bytes: usize,
    max_stack_frame_bytes: u32,
    max_witness_bytes: usize,
    max_transaction_bytes: usize,
    max_occupied_capacity_shannons: u64,
}

struct AnchorResult {
    verification: Result<u64, String>,
    transaction: TransactionView,
    elf_bytes: usize,
    max_stack_frame_bytes: u32,
    witness_bytes: usize,
    occupied_capacity_shannons: u64,
}

fn fixture() -> AnchorFixture {
    serde_json::from_str(include_str!("fixtures/capability_anchor_cases.json")).expect("canonical anchor fixture JSON")
}

fn options() -> CompileOptions {
    CompileOptions { target: Some("riscv64-elf".to_string()), target_profile: Some("ckb".to_string()), ..CompileOptions::default() }
}

fn compile(source: &str) -> cellscript::CompileResult {
    cellscript::compile(source, options()).unwrap_or_else(|error| panic!("anchor source must compile: {error}\n{source}"))
}

fn input(context: &mut Context, lock: packed::Script, type_script: packed::Script, amount: u64) -> packed::CellInput {
    let output = packed::CellOutput::new_builder()
        .capacity::<packed::Uint64>(100_000_000_000u64.pack())
        .lock(lock)
        .type_(Some(type_script).pack())
        .build();
    let out_point = context.create_cell(output, Bytes::copy_from_slice(&amount.to_le_bytes()));
    packed::CellInput::new_builder().previous_output(out_point).build()
}

fn output(lock: packed::Script, type_script: packed::Script) -> packed::CellOutput {
    packed::CellOutput::new_builder()
        .capacity::<packed::Uint64>(100_000_000_000u64.pack())
        .lock(lock)
        .type_(Some(type_script).pack())
        .build()
}

fn entry_witness(payload: Vec<u8>) -> Bytes {
    packed::WitnessArgs::new_builder().input_type(Some(Bytes::from(payload)).pack()).build().as_bytes()
}

fn plan(owner: [u8; 32], amounts: [u64; 2]) -> Vec<u8> {
    let elements = amounts
        .into_iter()
        .map(|amount| {
            let mut element = owner.to_vec();
            element.extend_from_slice(&amount.to_le_bytes());
            element
        })
        .collect::<Vec<_>>();
    cellscript::encode_bounded_output_plan_v1(&elements, 40, 2).expect("canonical anchor output plan")
}

fn run_anchor(mutation: Mutation) -> AnchorResult {
    assert_eq!(
        blake2b_256(POLICY_DATA),
        [
            0xe4, 0xce, 0xeb, 0x43, 0x42, 0x0a, 0x26, 0xba, 0x80, 0x79, 0x48, 0xa9, 0x36, 0x22, 0x17, 0xd0, 0xb2, 0x5b, 0x61, 0x4f,
            0xbe, 0x2c, 0x23, 0xc5, 0x3d, 0x4b, 0xdf, 0xf8, 0xb8, 0xef, 0x96, 0x60,
        ]
    );

    let order = compile(ORDER_SOURCE);
    let token = compile(TOKEN_SOURCE);
    let authorization = compile(AUTHORIZATION_SOURCE);
    assert_eq!(order.metadata.typed_semantics.foundation.entry_contract.exact_entry, "action:settle");
    assert_eq!(token.metadata.typed_semantics.foundation.entry_contract.exact_entry, "action:preserve");
    assert_eq!(authorization.metadata.typed_semantics.foundation.entry_contract.exact_entry, "lock:authorize");
    for artifact in [&order, &token, &authorization] {
        artifact.validate().expect("each anchor artifact must pass independent validation");
    }

    let order_elf = strip_vm_abi_trailer(&order.artifact_bytes);
    let token_elf = strip_vm_abi_trailer(&token.artifact_bytes);
    let authorization_elf = strip_vm_abi_trailer(&authorization.artifact_bytes);
    let elf_bytes = order_elf.len() + token_elf.len() + authorization_elf.len();
    let max_stack_frame_bytes = [&order, &token, &authorization]
        .into_iter()
        .flat_map(|artifact| artifact.verified_lowering_record.iter().flat_map(|record| &record.entries))
        .map(|entry| entry.frame_size_bytes)
        .max()
        .expect("anchor lowering records contain entry stack frames");

    let mut context = Context::new_with_deterministic_rng();
    context.set_capture_debug(true);
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());
    let order_out_point = context.deploy_cell(Bytes::copy_from_slice(order_elf));
    let token_out_point = context.deploy_cell(Bytes::copy_from_slice(token_elf));
    let authorization_out_point = context.deploy_cell(Bytes::copy_from_slice(authorization_elf));
    let dependency_data = if matches!(mutation, Mutation::Dependency) {
        Bytes::from_static(b"substituted-anchor-policy")
    } else {
        Bytes::from_static(POLICY_DATA)
    };
    let dependency_out_point = context.deploy_cell(dependency_data);

    let always_success_lock = context.build_script(&always_success_out_point, Bytes::new()).unwrap();
    let order_type = context.build_script(&order_out_point, Bytes::new()).unwrap();
    let token_type = context.build_script(&token_out_point, Bytes::new()).unwrap();
    let authorization_lock = context.build_script(&authorization_out_point, Bytes::new()).unwrap();

    let inputs = vec![
        input(&mut context, authorization_lock.clone(), token_type.clone(), 50),
        input(&mut context, always_success_lock.clone(), order_type.clone(), 10),
        input(&mut context, always_success_lock.clone(), order_type.clone(), 20),
    ];
    let outputs = vec![
        output(authorization_lock, token_type),
        output(always_success_lock.clone(), order_type.clone()),
        output(always_success_lock.clone(), order_type),
    ];
    let output_amounts: [u64; 3] = [
        if matches!(mutation, Mutation::TokenAmount) { 51 } else { 50 },
        if matches!(mutation, Mutation::OrderAmount) { 13 } else { 12 },
        18,
    ];
    let outputs_data = output_amounts.into_iter().map(|amount| Bytes::copy_from_slice(&amount.to_le_bytes())).collect::<Vec<_>>();

    let authorization_payload = authorization.metadata.locks[0]
        .entry_witness_args(&[EntryWitnessArg::U64(if matches!(mutation, Mutation::AuthorizationCredential) { 41 } else { 42 })])
        .expect("authorization entry payload");
    let order_plan = plan(always_success_lock.calc_script_hash().unpack(), [12, 18]);
    let order_payload = order.metadata.actions[0]
        .entry_witness_args(&[EntryWitnessArg::Bytes(order_plan)])
        .expect("bounded output plan entry payload");
    let witnesses = vec![entry_witness(authorization_payload), entry_witness(order_payload), Bytes::new()];
    let witness_bytes = witnesses.iter().map(Bytes::len).sum();
    let occupied_capacity_shannons = outputs
        .iter()
        .zip(&outputs_data)
        .map(|(cell, data)| {
            cell.occupied_capacity(Capacity::bytes(data.len()).expect("output data capacity"))
                .expect("occupied output capacity")
                .as_u64()
        })
        .sum();

    let transaction = context.complete_tx(
        TransactionBuilder::default()
            .inputs(inputs)
            .outputs(outputs)
            .outputs_data(outputs_data.pack())
            .witnesses(witnesses.pack())
            .cell_dep(packed::CellDep::new_builder().out_point(dependency_out_point).dep_type(DepType::Code).build())
            .build(),
    );
    let verification = context.verify_tx(&transaction, MAX_CYCLES).map_err(|error| format!("{error:#?}"));
    AnchorResult { verification, transaction, elf_bytes, max_stack_frame_bytes, witness_bytes, occupied_capacity_shannons }
}

#[test]
fn canonical_anchor_executes_three_cellscript_artifacts_in_one_transaction() {
    let fixture = fixture();
    assert_eq!(fixture.schema, "cellscript-capability-anchor-fixture-v1");
    assert_eq!(
        fixture.source_files,
        [
            "tests/fixtures/capability_anchor_order.cell",
            "tests/fixtures/capability_anchor_token.cell",
            "tests/fixtures/capability_anchor_authorization.cell",
        ]
    );
    assert_eq!(fixture.policy_data_hex, format!("0x{}", hex::encode(POLICY_DATA)));
    assert_eq!(fixture.artifacts, 3);
    assert_eq!(fixture.script_groups, 4);
    assert_eq!(fixture.positive_case, "settle_two_orders");
    let result = run_anchor(Mutation::None);
    let cycles = result.verification.expect("the canonical same-transaction anchor must pass");
    let transaction_bytes = result.transaction.data().serialized_size_in_block();
    assert_eq!(cycles, fixture.measured.cycles, "recorded anchor cycle measurement is stale");
    assert_eq!(result.elf_bytes, fixture.measured.combined_elf_bytes, "recorded anchor ELF measurement is stale");
    assert_eq!(
        result.max_stack_frame_bytes, fixture.measured.max_stack_frame_bytes,
        "recorded anchor stack-frame measurement is stale"
    );
    assert_eq!(result.witness_bytes, fixture.measured.witness_bytes, "recorded anchor witness measurement is stale");
    assert_eq!(transaction_bytes, fixture.measured.transaction_bytes, "recorded anchor transaction measurement is stale");
    assert_eq!(
        result.occupied_capacity_shannons, fixture.measured.occupied_capacity_shannons,
        "recorded anchor occupied-capacity measurement is stale"
    );
    assert!(cycles > 0 && cycles <= fixture.budgets.max_cycles, "anchor cycles outside the recorded budget: {cycles}");
    assert!(result.elf_bytes <= fixture.budgets.max_combined_elf_bytes, "combined anchor ELF bytes regressed: {}", result.elf_bytes);
    assert!(
        result.max_stack_frame_bytes <= fixture.budgets.max_stack_frame_bytes,
        "anchor stack frame regressed: {}",
        result.max_stack_frame_bytes
    );
    assert!(result.witness_bytes <= fixture.budgets.max_witness_bytes, "anchor witness bytes regressed: {}", result.witness_bytes);
    assert!(transaction_bytes <= fixture.budgets.max_transaction_bytes, "anchor transaction bytes regressed: {transaction_bytes}");
    assert!(
        result.occupied_capacity_shannons <= fixture.budgets.max_occupied_capacity_shannons,
        "anchor occupied capacity regressed: {}",
        result.occupied_capacity_shannons
    );
}

#[test]
fn canonical_anchor_rejects_each_role_and_dependency_substitution() {
    let fixture = fixture();
    assert_eq!(fixture.adversarial_cases.len(), 4);
    for case in fixture.adversarial_cases {
        assert!(run_anchor(case.mutation).verification.is_err(), "{} ({:?}) must fail the full transaction", case.name, case.mutation);
    }
}
