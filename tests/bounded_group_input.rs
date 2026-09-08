use ckb_testtool::ckb_types::bytes::Bytes;
use serde::Deserialize;

#[path = "support/ckb_script_runner.rs"]
#[allow(dead_code)]
mod ckb_script_runner;

use cellscript::simulate::{SimValue, SimulateError, SimulateInterpreter};
use ckb_script_runner::{build_simple_fixture, compile_cellscript_source_to_elf, execute_cellscript_script};

#[derive(Debug, Deserialize)]
struct Fixture {
    schema: String,
    source: String,
    entry: String,
    max_elements: usize,
    element_width_bytes: usize,
    selection: String,
    order: String,
    logical_identity_policy: String,
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
    inputs: Vec<Input>,
    expected_exit: i64,
}

#[derive(Debug, Deserialize)]
struct Input {
    scope: String,
    data_hex: String,
}

fn load_fixture() -> (Fixture, String) {
    let fixture: Fixture = serde_json::from_str(include_str!("fixtures/bounded_group_input_v1.json")).expect("fixture JSON");
    let source = include_str!("fixtures/bounded_group_input.cell").to_string();
    assert_eq!(fixture.source, "tests/fixtures/bounded_group_input.cell");
    (fixture, source)
}

fn decode_token(data: &[u8], width: usize) -> Result<SimValue, i64> {
    if data.len() != width || width != 16 {
        return Err(4);
    }
    let logical_id = u64::from_le_bytes(data[..8].try_into().expect("eight-byte identity"));
    let amount = u64::from_le_bytes(data[8..].try_into().expect("eight-byte amount"));
    Ok(SimValue::Struct {
        name: "Token".to_string(),
        fields: vec![
            ("logical_id".to_string(), SimValue::Integer(logical_id.into())),
            ("amount".to_string(), SimValue::Integer(amount.into())),
        ],
    })
}

fn simulator_exit(source: &str, fixture: &Fixture, case: &Case) -> i64 {
    let tokens = cellscript::lexer::lex(source).expect("fixture lex");
    let module = cellscript::parser::parse(&tokens).expect("fixture parse");
    let values = case
        .inputs
        .iter()
        .filter(|input| input.scope == "group")
        .map(|input| hex::decode(&input.data_hex).map_err(|_| 4).and_then(|data| decode_token(&data, fixture.element_width_bytes)))
        .collect::<Result<Vec<_>, _>>();
    let values = match values {
        Ok(values) => values,
        Err(code) => return code,
    };
    let mut simulator = SimulateInterpreter::new(&module, 10_000);
    match simulator.simulate_action(&fixture.entry, &[SimValue::Array(values)]) {
        Ok(_) => 0,
        Err(SimulateError::RuntimeError { code, .. }) => code as i64,
        Err(error) => panic!("unexpected simulator error for '{}': {error}", case.name),
    }
}

fn ckb_vm_result(elf: &[u8], case: &Case) -> (i64, u64) {
    let input_count = case.inputs.len().max(1);
    let mut transaction = build_simple_fixture(Bytes::default(), input_count, 1);
    transaction.current_type_script_input_indices =
        case.inputs.iter().enumerate().filter_map(|(index, input)| (input.scope == "group").then_some(index)).collect();
    for (cell, input) in transaction.inputs.iter_mut().zip(&case.inputs) {
        cell.data = Bytes::from(hex::decode(&input.data_hex).expect("fixture data hex"));
    }
    let result = execute_cellscript_script(elf, &transaction);
    (result.exit_code, result.cycles)
}

#[test]
fn shared_bounded_group_input_fixture_agrees_in_simulator_and_ckb_vm() {
    let (fixture, source) = load_fixture();
    assert_eq!(fixture.schema, "cellscript-bounded-group-input-fixture-v1");
    assert_eq!(fixture.max_elements, 3);
    assert_eq!(fixture.selection, "exact-current-type-script-group-input");
    assert_eq!(fixture.order, "canonical-group-relative-input-order");
    assert_eq!(fixture.logical_identity_policy, "application-defined-not-enforced-by-collection-selection");

    let elf = compile_cellscript_source_to_elf(&source, &fixture.entry, None);
    for case in &fixture.cases {
        assert_eq!(simulator_exit(&source, &fixture, case), case.expected_exit, "simulator case '{}'", case.name);
        let (exit, _) = ckb_vm_result(&elf, case);
        assert_eq!(exit, case.expected_exit, "CKB-VM case '{}'", case.name);
    }
}

#[test]
fn maximum_supported_group_cardinality_stays_within_the_recorded_resource_budget() {
    let (fixture, _) = load_fixture();
    assert_eq!(fixture.resource_evidence.maximum_source, "tests/fixtures/bounded_group_input_max.cell");
    assert_eq!(fixture.resource_evidence.maximum_elements, 1024);
    assert_eq!(fixture.resource_evidence.measurement_backend, "ckb-testtool-full-transaction-context");

    let source = include_str!("fixtures/bounded_group_input_max.cell");
    let elf = compile_cellscript_source_to_elf(source, &fixture.entry, None);
    assert!(elf.len() <= fixture.resource_evidence.max_elf_bytes, "maximum-N ELF grew to {} bytes", elf.len());

    let mut transaction = build_simple_fixture(Bytes::default(), fixture.resource_evidence.maximum_elements, 1);
    transaction.current_type_script_input_indices = (0..fixture.resource_evidence.maximum_elements).collect();
    for cell in &mut transaction.inputs {
        cell.data = Bytes::copy_from_slice(&1_u64.to_le_bytes());
    }
    let result = execute_cellscript_script(&elf, &transaction);
    assert_eq!(result.exit_code, 0, "maximum supported group must execute: {:?}", result.captured_debug);
    assert!(
        result.cycles <= fixture.resource_evidence.max_cycles,
        "maximum-N execution used {} cycles, above {}",
        result.cycles,
        fixture.resource_evidence.max_cycles
    );
}
