//! CKB script execution harness backed by ckb-testtool.
//!
//! Provides real CKB VM execution with full syscall context
//! (load_cell, load_script, load_witness, load_header, load_cell_data, etc.).
//! This is NOT a bare ckb-vm runner; it uses ckb-script's ScriptVerify
//! to handle the complete transaction verification pipeline.
//!
//! This harness is protocol-neutral. It does not contain iCKB-specific logic.

use ckb_testtool::ckb_types::{
    bytes::Bytes,
    core::{DepType, EpochNumberWithFraction, HeaderBuilder, TransactionBuilder, TransactionView},
    packed,
    prelude::*,
};
use ckb_testtool::context::Context;

const MAX_CYCLES: u64 = 10_000_000;

/// CellScript source for the pass-case VM harness test.
/// Uses ckb::current_script_hash() which invokes the real LOAD_SCRIPT_HASH
/// CKB syscall. This proves the CKB VM + syscall context works.
pub const VM_HARNESS_PASS_PROGRAM: &str = r#"
module vm_harness_pass

action verify_script_hash_syscall() -> u64 {
    verification
        let _hash = ckb::current_script_hash()
        return 0
}
"#;

/// CellScript source for the fail-case VM harness test.
/// Simply returns 1, proving the harness correctly captures script failures.
pub const VM_HARNESS_FAIL_PROGRAM: &str = r#"
module vm_harness_fail

action verify_always_reject() -> u64 {
    verification
        return 1
}
"#;

/// CellScript source for a minimal always-success lock script.
/// This is deployed as the lock script code cell for all non-under-test cells.
const ALWAYS_SUCCESS_PROGRAM: &str = r#"
module always_success_lock

action always_success() -> u64 {
    verification
        return 0
}
"#;

/// Entry action name for the pass-case harness test.
pub const VM_HARNESS_PASS_ACTION: &str = "verify_script_hash_syscall";

/// Entry action name for the fail-case harness test.
pub const VM_HARNESS_FAIL_ACTION: &str = "verify_always_reject";

/// CellScript source for the DAO accumulated-rate pass-case test.
/// Uses `dao::input_accumulated_rate(source::group_input(0))` which invokes
/// the real LOAD_HEADER CKB syscall. This proves DAO header reading works.
/// `dao::accumulated_rate(source::header_dep(0))` and the input accumulated-rate
/// variant both use LOAD_HEADER and parse the DAO field at absolute offset 160+8.
pub const VM_HARNESS_DAO_PASS_PROGRAM: &str = r#"
module vm_harness_dao_pass

action test_dao_input_accumulated_rate() -> u64 {
    verification
        let rate = dao::input_accumulated_rate(source::input(0))
        return 0
}
"#;

/// Entry action name for the DAO pass-case harness test.
pub const VM_HARNESS_DAO_PASS_ACTION: &str = "test_dao_input_accumulated_rate";

/// CellScript source for the DAO accumulated-rate missing-header-dep test.
/// Uses `dao::accumulated_rate(source::header_dep(0))`, which invokes the real
/// LOAD_HEADER CKB syscall and should fail when the transaction has no header dep.
pub const VM_HARNESS_DAO_MISSING_HEADER_DEP_PROGRAM: &str = r#"
module vm_harness_dao_missing_header_dep

action test_dao_missing_header_dep() -> u64 {
    verification
        let rate = dao::accumulated_rate(source::header_dep(0))
        return 0
}
"#;

/// Entry action name for the DAO missing-header-dep harness test.
pub const VM_HARNESS_DAO_MISSING_HEADER_DEP_ACTION: &str = "test_dao_missing_header_dep";

/// CellScript source for the DAO is_deposit_data pass-case test.
/// Uses `dao::is_deposit_data(source::input(0))` which invokes LOAD_CELL_DATA
/// to read 8 bytes and check if they are non-zero (deposit marker).
pub const VM_HARNESS_DAO_IS_DEPOSIT_PROGRAM: &str = r#"
module vm_harness_dao_deposit

action test_dao_is_deposit() -> u64 {
    verification
        let is_dep = dao::is_deposit_data(source::input(0))
        if is_dep {
            return 0
        }
        return 1
}
"#;
pub const VM_HARNESS_DAO_IS_DEPOSIT_ACTION: &str = "test_dao_is_deposit";

/// CellScript source for the DAO is_withdrawal_request_data pass-case test.
/// Uses `dao::is_withdrawal_request_data(source::input(0))` which invokes LOAD_CELL_DATA
/// to read 8 bytes and check if they are all zero (withdrawal request marker).
pub const VM_HARNESS_DAO_IS_WITHDRAWAL_PROGRAM: &str = r#"
module vm_harness_dao_withdrawal

action test_dao_is_withdrawal() -> u64 {
    verification
        let is_wd = dao::is_withdrawal_request_data(source::input(0))
        if is_wd {
            return 0
        }
        return 1
}
"#;
pub const VM_HARNESS_DAO_IS_WITHDRAWAL_ACTION: &str = "test_dao_is_withdrawal";

/// CellScript source for the ckb::cell_capacity pass-case test.
/// Uses `ckb::cell_capacity(source::input(0))` which invokes LOAD_CELL_BY_FIELD
/// with field=Capacity to read the cell's capacity value.
pub const VM_HARNESS_CELL_CAPACITY_PROGRAM: &str = r#"
module vm_harness_cell_capacity

action test_cell_capacity() -> u64 {
    verification
        let cap = ckb::cell_capacity(source::input(0))
        if cap > 0 {
            return 0
        }
        return 1
}
"#;
pub const VM_HARNESS_CELL_CAPACITY_ACTION: &str = "test_cell_capacity";

/// CellScript source for the dao::has_dao_type negative test.
/// Uses `dao::has_dao_type(source::input(0))` which invokes LOAD_CELL_BY_FIELD
/// with field=TypeHash. On a cell without DAO type script, it returns false.
pub const VM_HARNESS_DAO_HAS_TYPE_NEG_PROGRAM: &str = r#"
module vm_harness_dao_has_type_neg

action test_dao_has_no_type() -> u64 {
    verification
        let has_dao = dao::has_dao_type(source::input(0))
        if has_dao {
            return 1
        }
        return 0
}
"#;
pub const VM_HARNESS_DAO_HAS_TYPE_NEG_ACTION: &str = "test_dao_has_no_type";

/// CellScript source for the ckb::cell_occupied_capacity pass-case test.
/// Uses `ckb::cell_occupied_capacity(source::input(0))` which invokes
/// LOAD_CELL_BY_FIELD(OccupiedCapacity) to read the CKB-native occupied
/// capacity in shannons.
pub const VM_HARNESS_OCCUPIED_CAPACITY_PROGRAM: &str = r#"
module vm_harness_occupied_capacity

action test_occupied_capacity() -> u64 {
    verification
        let occupied = ckb::cell_occupied_capacity(source::input(0))
        if occupied > 0 {
            return 0
        }
        return 1
}
"#;
pub const VM_HARNESS_OCCUPIED_CAPACITY_ACTION: &str = "test_occupied_capacity";

/// CellScript source for the ckb::cell_data_size pass-case test.
/// Uses `ckb::cell_data_size(source::input(0))` which invokes LOAD_CELL_DATA
/// to probe the cell data byte length.
pub const VM_HARNESS_CELL_DATA_SIZE_PROGRAM: &str = r#"
module vm_harness_cell_data_size

action test_cell_data_size() -> u64 {
    verification
        let size = ckb::cell_data_size(source::input(0))
        return 0
}
"#;
pub const VM_HARNESS_CELL_DATA_SIZE_ACTION: &str = "test_cell_data_size";

/// CellScript source for a CellDep data-size pass-case test.
/// Uses `ckb::cell_data_size(source::cell_dep(0))` so the fixture must include
/// the deployed dependency as a transaction CellDep, not just deploy it in the
/// test context.
pub const VM_HARNESS_CELL_DEP_DATA_SIZE_PROGRAM: &str = r#"
module vm_harness_cell_dep_data_size

action test_cell_dep_data_size() -> u64 {
    verification
        let size = ckb::cell_data_size(source::cell_dep(0))
        if size != 4 {
            return 1
        }
        return 0
}
"#;
pub const VM_HARNESS_CELL_DEP_DATA_SIZE_ACTION: &str = "test_cell_dep_data_size";

/// CellScript source for a combined iCKB deposit scenario test.
/// Uses multiple syscalls together to verify the iCKB deposit verification path:
///
/// 1. LOAD_CELL_DATA to classify cell (is_deposit_data)
/// 2. LOAD_CELL_BY_FIELD to read cell capacity
/// 3. LOAD_CELL_BY_FIELD(OccupiedCapacity) for occupied capacity
/// 4. LOAD_HEADER for DAO accumulated rate
///
/// This simulates the core iCKB deposit verification logic in a single script.
pub const VM_HARNESS_ICKB_DEPOSIT_PROGRAM: &str = r#"
module vm_harness_ickb_deposit

action test_ickb_deposit_verification() -> u64 {
    verification
        let input = source::input(0)
        // Step 1: Verify the input is a DAO deposit cell (8 zero bytes)
        let is_dep = dao::is_deposit_data(input)
        if !is_dep {
            return 1
        }
        // Step 2: Read cell capacity (must be positive)
        let cap = ckb::cell_capacity(input)
        if cap == 0 {
            return 2
        }
        // Step 3: Read DAO accumulated rate from header
        let rate = dao::input_accumulated_rate(input)
        // Step 4: All checks pass
        return 0
}
"#;
pub const VM_HARNESS_ICKB_DEPOSIT_ACTION: &str = "test_ickb_deposit_verification";

/// Result of executing a CKB script via ckb-testtool.
#[derive(Debug, Clone)]
pub struct CkbScriptExecutionResult {
    /// 0 for pass, non-zero for script error.
    pub exit_code: i64,
    /// Cycles consumed (0 on error).
    pub cycles: u64,
    /// Captured debug print messages from the script.
    pub captured_debug: Vec<String>,
}

/// A cell in a CKB transaction fixture.
#[derive(Debug, Clone)]
pub struct FixtureCell {
    pub capacity: u64,
    pub type_script: Option<packed::Script>,
    pub data: Bytes,
}

/// Header fields that are exposed by CKB's `LOAD_HEADER_BY_FIELD` syscall.
#[derive(Debug, Clone, Copy)]
pub struct FixtureHeaderContext {
    pub number: u64,
    pub timestamp: u64,
    pub epoch_number: u64,
    pub epoch_index: u64,
    pub epoch_length: u64,
}

/// A complete CKB VM fixture for script execution.
#[derive(Debug, Clone)]
pub struct CkbVmFixture {
    /// Script args for the CellScript-compiled type script being tested.
    pub script_args: Bytes,
    /// Input cells.
    pub inputs: Vec<FixtureCell>,
    /// Input indexes that carry the CellScript type script under test.
    ///
    /// This is separate from `FixtureCell::type_script` so tests can express a
    /// real type-script group whose first member is not transaction input 0.
    pub current_type_script_input_indices: Vec<usize>,
    /// Output cells.
    pub outputs: Vec<FixtureCell>,
    /// Additional cell deps (beyond the script code cell itself).
    pub cell_deps: Vec<FixtureCell>,
    /// Witness data per input (must match input count or be empty).
    pub witnesses: Vec<Bytes>,
    /// Header deps to include in the transaction.
    /// Each entry is a 32-byte DAO field (packed Byte32) for the header.
    pub header_dao_fields: Vec<[u8; 32]>,
    /// Optional per-header number and epoch fields. Missing entries retain the
    /// historical all-zero header used by existing fixtures.
    pub header_contexts: Vec<FixtureHeaderContext>,
    /// Whether to link input cells with their block headers.
    /// If true, input[i] is linked to header_dao_fields[i]'s block.
    pub link_inputs_to_headers: bool,
}

/// Compile a CellScript source string to RISC-V ELF bytes with a specific entry action.
pub fn compile_cellscript_source_to_elf(source: &str, entry_action: &str, primitive_compat: Option<&str>) -> Vec<u8> {
    let options = cellscript::CompileOptions {
        target: Some("riscv64-elf".to_string()),
        target_profile: Some("ckb".to_string()),
        primitive_compat: primitive_compat.map(|s| s.to_string()),
        ..cellscript::CompileOptions::default()
    };
    let result = cellscript::compile(source, options).unwrap_or_else(|err| panic!("failed to compile: {}", err.message));
    assert!(
        matches!(result.artifact_format, cellscript::ArtifactFormat::RiscvElf),
        "expected ELF artifact, got {:?}",
        result.artifact_format
    );
    // Verify the entry action exists in the compiled metadata.
    assert!(
        result.metadata.actions.iter().any(|a| a.name == entry_action),
        "entry action '{}' not found in compiled metadata",
        entry_action
    );
    // Strip the VM ABI trailer before feeding to ckb-testtool,
    // which expects a bare RISC-V ELF.
    cellscript::strip_vm_abi_trailer(&result.artifact_bytes).to_vec()
}

/// Return the lock hash used by `execute_cellscript_script` for its deterministic
/// always-success lock deployment. This lets witness plans bind an exact output
/// lock without weakening the script-side lock policy.
#[allow(dead_code)]
pub fn deterministic_always_success_lock_hash() -> [u8; 32] {
    let mut context = Context::new_with_deterministic_rng();
    let always_success_elf = compile_cellscript_source_to_elf(ALWAYS_SUCCESS_PROGRAM, "always_success", None);
    let out_point = context.deploy_cell(Bytes::copy_from_slice(&always_success_elf));
    let lock = context.build_script(&out_point, Bytes::default()).expect("build deterministic always-success lock script");
    lock.calc_script_hash().unpack()
}

/// Execute a CellScript-compiled ELF against a CKB VM fixture.
///
/// This deploys the ELF, creates the transaction from the fixture,
/// and runs `Context::verify_tx()` with full CKB syscall context.
///
/// The ELF is deployed as a type script code cell. The always_success
/// lock script is also deployed for cells that use "always_success" lock.
pub fn execute_cellscript_script(elf_bytes: &[u8], fixture: &CkbVmFixture) -> CkbScriptExecutionResult {
    execute_cellscript_script_with_transaction_transform(elf_bytes, fixture, |tx, _| tx)
}

/// Execute a fixture after applying a deterministic witness-only transform to
/// the completed transaction. The callback also receives the exact current
/// type Script so SDK signing-message tests can construct its ScriptGroup.
#[allow(dead_code)]
pub fn execute_cellscript_script_with_transaction_transform<F>(
    elf_bytes: &[u8],
    fixture: &CkbVmFixture,
    transform: F,
) -> CkbScriptExecutionResult
where
    F: FnOnce(TransactionView, packed::Script) -> TransactionView,
{
    let mut context = Context::new_with_deterministic_rng();
    context.set_capture_debug(true);

    // Compile and deploy the always_success lock script.
    // This is a real RISC-V ELF (not an empty cell) so that CKB VM can
    // parse and execute it successfully as a lock script.
    let always_success_elf = compile_cellscript_source_to_elf(ALWAYS_SUCCESS_PROGRAM, "always_success", None);
    let always_success_out_point = context.deploy_cell(Bytes::copy_from_slice(&always_success_elf));

    // Deploy the CellScript-compiled script code as a cell.
    let script_out_point = context.deploy_cell(Bytes::copy_from_slice(elf_bytes));

    // Build the type script referencing the deployed CellScript code.
    // build_script defaults to ScriptHashType::Type which is what we need
    // for on-chain CKB type scripts.
    let type_script =
        context.build_script(&script_out_point, fixture.script_args.clone()).expect("build type script from deployed ELF");

    // Build the always_success lock script.
    let always_success_lock =
        context.build_script(&always_success_out_point, Bytes::default()).expect("build always_success lock script");

    // Create input cells with always_success lock.
    let input_out_points: Vec<packed::OutPoint> = fixture
        .inputs
        .iter()
        .enumerate()
        .map(|(index, cell)| {
            let input_type_script = if fixture.current_type_script_input_indices.contains(&index) {
                Some(type_script.clone())
            } else {
                cell.type_script.clone()
            };
            let output = packed::CellOutput::new_builder()
                .capacity::<packed::Uint64>(cell.capacity.pack())
                .lock(always_success_lock.clone())
                .type_(packed::ScriptOpt::from(input_type_script))
                .build();
            context.create_cell(output, cell.data.clone())
        })
        .collect();

    // Create cell deps that the script can reference via load_cell. Tests may
    // attach a Type Script when the dependency identity itself is part of the
    // contract under test.
    let dep_out_points: Vec<packed::OutPoint> = fixture
        .cell_deps
        .iter()
        .map(|cell| {
            let output = packed::CellOutput::new_builder()
                .capacity::<packed::Uint64>(cell.capacity.pack())
                .lock(always_success_lock.clone())
                .type_(packed::ScriptOpt::from(cell.type_script.clone()))
                .build();
            context.create_cell(output, cell.data.clone())
        })
        .collect();

    // Create header deps with DAO fields.
    // Each header is built with a DAO field containing the accumulated rate,
    // then inserted into the context and referenced by hash in the transaction.
    let header_hashes: Vec<packed::Byte32> = fixture
        .header_dao_fields
        .iter()
        .enumerate()
        .map(|(index, dao_bytes)| {
            let dao_packed: packed::Byte32 = dao_bytes.pack();
            let mut builder = HeaderBuilder::default().number(0u64).dao(dao_packed);
            if let Some(header) = fixture.header_contexts.get(index) {
                builder = builder.number(header.number).timestamp(header.timestamp).epoch(EpochNumberWithFraction::new(
                    header.epoch_number,
                    header.epoch_index,
                    header.epoch_length,
                ));
            }
            let header = builder.build();
            let hash = header.hash();
            context.insert_header(header);
            hash
        })
        .collect();

    // Link input cells with their block headers if requested.
    // This is needed for dao::input_accumulated_rate() which reads the
    // DAO field from the input's committed header via LOAD_HEADER.
    if fixture.link_inputs_to_headers {
        for (i, input_op) in input_out_points.iter().enumerate() {
            let header_hash = header_hashes.get(i).or_else(|| header_hashes.first()).expect("at least one header dep");
            context.link_cell_with_block(input_op.clone(), header_hash.clone(), i);
        }
    }

    // Build output cells. At least one output must carry the type script under test
    // so that the script is actually invoked as a type script.
    let output_cells: Vec<packed::CellOutput> =
        fixture.outputs.iter().map(|cell| build_cell_output(cell, &type_script, &always_success_lock)).collect();

    let outputs_data = fixture.outputs.iter().map(|cell| cell.data.clone()).collect::<Vec<_>>();

    // Build witnesses. If not provided, use empty defaults.
    let witnesses: Vec<Bytes> = if fixture.witnesses.is_empty() {
        (0..input_out_points.len()).map(|_| Bytes::default()).collect()
    } else {
        fixture.witnesses.clone()
    };

    // Assemble the transaction with header deps.
    let mut tx_builder = TransactionBuilder::default()
        .inputs(input_out_points.into_iter().map(|op| packed::CellInput::new_builder().previous_output(op).build()))
        .outputs(output_cells)
        .outputs_data(outputs_data.pack())
        .witnesses(witnesses.pack());

    // Add header deps to the transaction.
    for header_hash in &header_hashes {
        tx_builder = tx_builder.header_dep(header_hash.clone());
    }
    for dep_out_point in dep_out_points {
        tx_builder = tx_builder.cell_dep(packed::CellDep::new_builder().out_point(dep_out_point).dep_type(DepType::Code).build());
    }

    let tx = tx_builder.build();
    let tx = context.complete_tx(tx);
    let tx = transform(tx, type_script);

    // Execute via ckb-script ScriptVerify with full CKB syscall context.
    let verify_result = context.verify_tx(&tx, MAX_CYCLES);
    match verify_result {
        Ok(cycles) => CkbScriptExecutionResult {
            exit_code: 0,
            cycles,
            captured_debug: context.captured_messages().into_iter().map(|m| m.message).collect(),
        },
        Err(verify_failure) => {
            let debug_messages: Vec<String> = context.captured_messages().into_iter().map(|m| m.message).collect();
            // Extract error source details for debugging.
            let error_detail = format!("{:#?}", verify_failure);
            let exit_code = parse_ckb_script_error_code(&error_detail).unwrap_or(-1);
            let mut all_debug = debug_messages;
            all_debug.push(format!("CKB_ERROR: {}", error_detail));
            CkbScriptExecutionResult { exit_code, cycles: 0, captured_debug: all_debug }
        }
    }
}

fn parse_ckb_script_error_code(error: &str) -> Option<i64> {
    for marker in ["error code ", "error code: "] {
        if let Some(start) = error.find(marker).map(|index| index + marker.len()) {
            let digits: String = error[start..].chars().take_while(|ch| ch.is_ascii_digit() || *ch == '-').collect();
            if let Ok(code) = digits.parse() {
                return Some(code);
            }
        }
    }
    None
}

/// Build a simple harness fixture for testing CellScript script execution.
/// Uses always_success lock for all cells and the current ELF as type script.
pub fn build_simple_fixture(script_args: Bytes, input_count: usize, output_count: usize) -> CkbVmFixture {
    let inputs =
        (0..input_count).map(|_| FixtureCell { capacity: 100_000_000_000, type_script: None, data: Bytes::default() }).collect();
    let outputs = (0..output_count)
        .map(|_| FixtureCell {
            capacity: 100_000_000_000,
            type_script: None, // current_under_test set by harness
            data: Bytes::default(),
        })
        .collect();
    CkbVmFixture {
        script_args,
        inputs,
        current_type_script_input_indices: Vec::new(),
        outputs,
        cell_deps: Vec::new(),
        witnesses: Vec::new(),
        header_dao_fields: Vec::new(),
        header_contexts: Vec::new(),
        link_inputs_to_headers: false,
    }
}

/// Build a CellOutput from a fixture cell, attaching the type script
/// under test and always_success lock.
fn build_cell_output(
    cell: &FixtureCell,
    default_type_script: &packed::Script,
    always_success_lock: &packed::Script,
) -> packed::CellOutput {
    let type_script = cell.type_script.as_ref().unwrap_or(default_type_script);
    packed::CellOutput::new_builder()
        .capacity::<packed::Uint64>(cell.capacity.pack())
        .lock(always_success_lock.clone())
        .type_(packed::ScriptOpt::from(type_script.clone()))
        .build()
}

/// Build a DAO fixture for testing DAO accumulated-rate scripts.
/// Creates a header with the given DAO accumulated rate and includes it as a header dep.
pub fn build_dao_fixture(script_args: Bytes, accumulated_rate: u64, input_count: usize, output_count: usize) -> CkbVmFixture {
    let dao_field = make_dao_field(accumulated_rate);
    let inputs =
        (0..input_count).map(|_| FixtureCell { capacity: 100_000_000_000, type_script: None, data: Bytes::default() }).collect();
    let outputs =
        (0..output_count).map(|_| FixtureCell { capacity: 100_000_000_000, type_script: None, data: Bytes::default() }).collect();
    CkbVmFixture {
        script_args,
        inputs,
        current_type_script_input_indices: Vec::new(),
        outputs,
        cell_deps: Vec::new(),
        witnesses: Vec::new(),
        header_dao_fields: vec![dao_field],
        header_contexts: Vec::new(),
        link_inputs_to_headers: true,
    }
}

/// Build a DAO cell-data classification fixture.
/// Each input cell gets the specified data bytes.
/// No header deps or DAO accumulated rate — this fixture is for
/// `is_deposit_data` / `is_withdrawal_request_data` / `has_dao_type` / `cell_capacity`
/// tests that use LOAD_CELL_DATA or LOAD_CELL_BY_FIELD on inputs.
pub fn build_dao_data_fixture(script_args: Bytes, input_data: Vec<Bytes>, output_count: usize) -> CkbVmFixture {
    let inputs: Vec<FixtureCell> =
        input_data.into_iter().map(|data| FixtureCell { capacity: 100_000_000_000, type_script: None, data }).collect();
    let outputs =
        (0..output_count).map(|_| FixtureCell { capacity: 100_000_000_000, type_script: None, data: Bytes::default() }).collect();
    CkbVmFixture {
        script_args,
        inputs,
        current_type_script_input_indices: Vec::new(),
        outputs,
        cell_deps: Vec::new(),
        witnesses: Vec::new(),
        header_dao_fields: Vec::new(),
        header_contexts: Vec::new(),
        link_inputs_to_headers: false,
    }
}

/// Construct a 32-byte CKB DAO field with the given accumulated rate.
/// Layout: [C(8 bytes LE) | AR(8 bytes LE) | padding(16 bytes)]
/// The accumulated rate is at offset 8 within the DAO field, matching
/// iCKB's `AR_OFFSET` and CellScript's `CKB_DAO_FIELD_ACCUMULATED_RATE_OFFSET`.
pub fn make_dao_field(accumulated_rate: u64) -> [u8; 32] {
    let mut dao = [0u8; 32];
    // Bytes 0-7: C (compensation, leave as 0)
    // Bytes 8-15: AR (accumulated rate, little-endian u64)
    dao[8..16].copy_from_slice(&accumulated_rate.to_le_bytes());
    // Bytes 16-31: leave as 0
    dao
}

/// Load an original iCKB script binary from the test fixtures directory.
/// Returns the raw ELF bytes for deployment as a CKB code cell.
pub fn load_original_ickb_binary(name: &str) -> Vec<u8> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("benchmarks")
        .join("ickb_diff")
        .join("original_binaries")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|err| panic!("failed to load original iCKB binary {:?}: {}", path, err))
}

/// Patch the DAO_HASH constant in the iCKB Logic binary so it matches the
/// DAO type script hash produced by ckb-testtool (hash_type=Data).
///
/// The original iCKB binary hardcodes `DAO_HASH = cc77c4de...` which is
/// `calc_script_hash(Script{code_hash=82d76d1b..., hash_type=Type, args=empty})`
/// — the mainnet DAO type script hash. In ckb-testtool, deploying the DAO
/// binary via `deploy_cell` uses `hash_type=Data`, producing a different
/// type script hash. This function replaces the hardcoded DAO_HASH with
/// the test-environment DAO type hash so the original iCKB script can
/// correctly identify DAO cells.
///
/// This is **not** a fidelity compromise — it's the correct engineering
/// choice: we verify functional correctness and differential equivalence
/// under a controlled identity system, not mainnet identity reconstruction.
pub fn patch_ickb_logic_dao_hash(ickb_logic_elf: &mut [u8], new_dao_hash: &[u8; 32]) {
    // The DAO_HASH constant is at offset 0x360 in the iCKB Logic binary.
    // It appears exactly once (verified by hex search).
    let offset = 0x360;
    assert!(ickb_logic_elf.len() > offset + 32, "iCKB Logic binary too small for DAO_HASH patch");
    // Verify the current value matches the expected mainnet DAO_HASH.
    let expected_mainnet_dao_hash: [u8; 32] = [
        0xcc, 0x77, 0xc4, 0xde, 0xac, 0x05, 0xd6, 0x8a, 0xb5, 0xb2, 0x68, 0x28, 0xf0, 0xbf, 0x45, 0x65, 0xa8, 0xd7, 0x31, 0x13, 0xd7,
        0xbb, 0x7e, 0x92, 0xb8, 0x36, 0x2b, 0x8a, 0x74, 0xe5, 0x8e, 0x58,
    ];
    let current_hash = &ickb_logic_elf[offset..offset + 32];
    assert_eq!(
        current_hash,
        &expected_mainnet_dao_hash[..],
        "DAO_HASH at offset 0x360 doesn't match expected mainnet value — binary may have changed"
    );
    ickb_logic_elf[offset..offset + 32].copy_from_slice(new_dao_hash);
}
