use ckb_testtool::ckb_types::{bytes::Bytes, packed, prelude::*};
use serde::Deserialize;

#[path = "support/ckb_script_runner.rs"]
#[allow(dead_code)]
mod ckb_script_runner;

use cellscript::simulate::{SimValue, SimulateError, SimulateInterpreter, TraceEvent};
use ckb_script_runner::{
    build_simple_fixture, compile_cellscript_source_to_elf, deterministic_always_success_lock_hash,
    deterministic_always_success_script, execute_cellscript_script,
};

#[derive(Debug, Deserialize)]
struct Fixture {
    schema: String,
    source: String,
    entry: String,
    max_elements: usize,
    element_width_bytes: usize,
    output_width_bytes: usize,
    capacity_floor_shannons: u64,
    selection: String,
    order: String,
    correspondence: String,
    identity_policy: String,
    equal_plan_bytes_allowed: bool,
    resource_evidence: ResourceEvidence,
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
struct ResourceEvidence {
    maximum_source: String,
    maximum_elements: usize,
    measurement_backend: String,
    max_elf_bytes: usize,
    max_cycles: u64,
}

#[derive(Debug, Deserialize)]
struct Case {
    name: String,
    plans: Vec<Plan>,
    outputs: Vec<Output>,
    codec: String,
    simulator_expected_exit: i64,
    expected_exit: i64,
}

#[derive(Debug, Deserialize)]
struct Plan {
    owner: String,
    amount: u64,
}

#[derive(Debug, Deserialize)]
struct Output {
    scope: String,
    lock: String,
    amount: u64,
    capacity_shannons: u64,
}

fn load_fixture() -> (Fixture, String) {
    let fixture: Fixture = serde_json::from_str(include_str!("fixtures/bounded_output_plan_v1.json")).expect("fixture JSON");
    let source = include_str!("fixtures/bounded_output_plan.cell").to_string();
    assert_eq!(fixture.source, "tests/fixtures/bounded_output_plan.cell");
    (fixture, source)
}

fn simulator_exit(source: &str, fixture: &Fixture, case: &Case) -> (i64, usize) {
    let tokens = cellscript::lexer::lex(source).expect("fixture lex");
    let module = cellscript::parser::parse(&tokens).expect("fixture parse");
    let plans = case
        .plans
        .iter()
        .map(|plan| SimValue::Struct {
            name: "Plan".to_string(),
            fields: vec![
                ("owner".to_string(), SimValue::Simulated { ty: "Address".to_string(), description: plan.owner.clone() }),
                ("amount".to_string(), SimValue::Integer(plan.amount.into())),
            ],
        })
        .collect();
    let mut simulator = SimulateInterpreter::new(&module, 10_000);
    match simulator.simulate_action(&fixture.entry, &[SimValue::Array(plans)]) {
        Ok(result) => (0, result.trace.iter().filter(|event| matches!(event, TraceEvent::Create { .. })).count()),
        Err(SimulateError::RuntimeError { code, .. }) => (code as i64, 0),
        Err(error) => panic!("unexpected simulator error for '{}': {error}", case.name),
    }
}

fn plan_payload(case: &Case, owner_hash: [u8; 32], max_elements: usize) -> Bytes {
    let elements = case
        .plans
        .iter()
        .map(|plan| {
            let mut element = if plan.owner == "zero" { vec![0_u8; 32] } else { owner_hash.to_vec() };
            element.extend_from_slice(&plan.amount.to_le_bytes());
            element
        })
        .collect::<Vec<_>>();
    let mut plan = if case.codec == "canonical_unchecked_count" {
        let mut payload = b"CSBPLv1\0".to_vec();
        payload.extend_from_slice(&u32::try_from(elements.len()).unwrap().to_le_bytes());
        payload.extend(elements.into_iter().flatten());
        payload
    } else {
        cellscript::encode_bounded_output_plan_v1(&elements, 40, max_elements).expect("canonical bounded output plan")
    };
    match case.codec.as_str() {
        "canonical" | "canonical_unchecked_count" => {}
        "wrong_magic" => plan[0] ^= 0xff,
        "trailing_byte" => plan.push(0),
        other => panic!("unknown fixture codec {other}"),
    }
    let mut payload = b"CSARGv1\0".to_vec();
    payload.extend_from_slice(&u32::try_from(plan.len()).unwrap().to_le_bytes());
    payload.extend_from_slice(&plan);
    Bytes::from(payload)
}

fn ckb_vm_result(elf: &[u8], fixture: &Fixture, case: &Case) -> (i64, u64) {
    let owner = deterministic_always_success_lock_hash();
    let payload = plan_payload(case, owner, fixture.max_elements);
    let witness = packed::WitnessArgs::new_builder().input_type(Some(payload).pack()).build();
    let mut transaction = build_simple_fixture(Bytes::default(), 1, case.outputs.len());
    transaction.current_type_script_input_indices = vec![0];
    transaction.witnesses = vec![witness.as_bytes()];
    for (cell, output) in transaction.outputs.iter_mut().zip(&case.outputs) {
        assert_eq!(output.lock, "output_lock");
        cell.capacity = output.capacity_shannons;
        cell.data = Bytes::copy_from_slice(&output.amount.to_le_bytes());
        if output.scope == "outside_group" {
            cell.type_script = Some(deterministic_always_success_script(Bytes::from_static(b"foreign")));
        } else {
            assert_eq!(output.scope, "group");
        }
    }
    let result = execute_cellscript_script(elf, &transaction);
    (result.exit_code, result.cycles)
}

#[test]
fn shared_bounded_output_plan_fixture_covers_simulator_semantics_and_ckb_vm_correspondence() {
    let (fixture, source) = load_fixture();
    assert_eq!(fixture.schema, "cellscript-bounded-output-plan-fixture-v1");
    assert_eq!(fixture.max_elements, 3);
    assert_eq!(fixture.element_width_bytes, 40);
    assert_eq!(fixture.output_width_bytes, 8);
    assert_eq!(fixture.capacity_floor_shannons, 10_000_000_000);
    assert_eq!(fixture.selection, "exact-current-type-script-group-output");
    assert_eq!(fixture.order, "plan-index-equals-canonical-group-output-index");
    assert_eq!(fixture.correspondence, "exactly-one-group-output-per-plan-element");
    assert_eq!(fixture.identity_policy, "fresh-output-outpoint-plus-type-group-ordinal");
    assert!(fixture.equal_plan_bytes_allowed);

    let elf = compile_cellscript_source_to_elf(&source, &fixture.entry, None);
    for case in &fixture.cases {
        let (simulator, creates) = simulator_exit(&source, &fixture, case);
        assert_eq!(simulator, case.simulator_expected_exit, "simulator case '{}'", case.name);
        if simulator == 0 {
            assert_eq!(creates, case.plans.len(), "simulator create count for '{}'", case.name);
        }
        let (exit, _) = ckb_vm_result(&elf, &fixture, case);
        assert_eq!(exit, case.expected_exit, "CKB-VM case '{}'", case.name);
    }
}

#[test]
fn maximum_encodable_output_plan_stays_within_the_recorded_resource_budget() {
    let (fixture, _) = load_fixture();
    assert_eq!(fixture.resource_evidence.maximum_source, "tests/fixtures/bounded_output_plan_max.cell");
    assert_eq!(fixture.resource_evidence.maximum_elements, 101);
    assert_eq!(fixture.resource_evidence.measurement_backend, "ckb-testtool-full-transaction-context");

    let source = include_str!("fixtures/bounded_output_plan_max.cell");
    let elf = compile_cellscript_source_to_elf(source, &fixture.entry, None);
    assert!(elf.len() <= fixture.resource_evidence.max_elf_bytes, "maximum-N ELF grew to {} bytes", elf.len());

    let owner = deterministic_always_success_lock_hash();
    let plans = (0..fixture.resource_evidence.maximum_elements)
        .map(|_| Plan { owner: "output_lock".to_string(), amount: 1 })
        .collect::<Vec<_>>();
    let outputs = (0..fixture.resource_evidence.maximum_elements)
        .map(|_| Output { scope: "group".to_string(), lock: "output_lock".to_string(), amount: 1, capacity_shannons: 100_000_000_000 })
        .collect::<Vec<_>>();
    let case = Case {
        name: "maximum_encodable_n".to_string(),
        plans,
        outputs,
        codec: "canonical".to_string(),
        simulator_expected_exit: 0,
        expected_exit: 0,
    };
    let payload = plan_payload(&case, owner, fixture.resource_evidence.maximum_elements);
    assert!(payload.len() <= 4096);
    let witness = packed::WitnessArgs::new_builder().input_type(Some(payload).pack()).build();
    let mut transaction = build_simple_fixture(Bytes::default(), 1, fixture.resource_evidence.maximum_elements);
    transaction.current_type_script_input_indices = vec![0];
    transaction.witnesses = vec![witness.as_bytes()];
    for output in &mut transaction.outputs {
        output.data = Bytes::copy_from_slice(&1_u64.to_le_bytes());
    }
    let result = execute_cellscript_script(&elf, &transaction);
    assert_eq!(result.exit_code, 0, "maximum output plan must execute: {:?}", result.captured_debug);
    assert!(
        result.cycles <= fixture.resource_evidence.max_cycles,
        "maximum-N execution used {} cycles, above {}",
        result.cycles,
        fixture.resource_evidence.max_cycles
    );
}
