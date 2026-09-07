use crate::aggregate_lowering::{
    action_has_group_amount_conservation_evidence, body_contains_runtime_helper, xudt_group_amount_conservation_type,
    FUNGIBLE_TYPE_GROUP_V1_CODEGEN_HELPER, XUDT_GROUP_AMOUNT_CONSERVED_CODEGEN_HELPER,
};
use crate::ast::{BinaryOp, ParamSource, UnaryOp};
use crate::ckb_abi;
use crate::error::{CompileError, Result};
use crate::flow::FLOW_STATE_FIELD_NAME;
use crate::ir::*;
use crate::runtime_errors::CellScriptRuntimeError;
use crate::{ArtifactFormat, TargetProfile, ENTRY_WITNESS_ABI_MAGIC};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap};

mod abi;
mod assembler;
mod calls;
mod cell_ops;
mod collections;
mod expr;
mod frame;
mod policy;
mod runtime;
mod runtime_gather;
mod schema;
#[cfg(not(feature = "wasm"))]
pub(crate) use abi::{entry_param_abi_sources, EntryParamAbiSource};
pub use assembler::BackendShapeMetrics;
use assembler::*;
use cell_ops::{CellFieldHashCheck, CellFieldHashLocation};
pub use runtime::{
    generate, generate_with_evidence, GeneratedArtifact, MachineBlockEvidence, MachineEdgeEvidence, MachineEdgeKindEvidence,
    MachineLayoutEvidence, MachineTerminatorEvidence,
};

const CKB_LOAD_HEADER_SYSCALL_NUMBER: u64 = ckb_abi::syscall::LOAD_HEADER;
const CKB_LOAD_HEADER_BY_FIELD_SYSCALL_NUMBER: u64 = ckb_abi::syscall::LOAD_HEADER_BY_FIELD;
const CKB_LOAD_INPUT_BY_FIELD_SYSCALL_NUMBER: u64 = ckb_abi::syscall::LOAD_INPUT_BY_FIELD;
const CKB_LOAD_WITNESS_SYSCALL_NUMBER: u64 = ckb_abi::syscall::LOAD_WITNESS;
const CKB_LOAD_SCRIPT_SYSCALL_NUMBER: u64 = ckb_abi::syscall::LOAD_SCRIPT;
const CKB_LOAD_CELL_BY_FIELD_SYSCALL_NUMBER: u64 = ckb_abi::syscall::LOAD_CELL_BY_FIELD;
const CKB_LOAD_CELL_DATA_SYSCALL_NUMBER: u64 = ckb_abi::syscall::LOAD_CELL_DATA;
const CKB_LOAD_SCRIPT_HASH_SYSCALL_NUMBER: u64 = ckb_abi::syscall::LOAD_SCRIPT_HASH;
const CKB_HEADER_FIELD_EPOCH_NUMBER: u64 = ckb_abi::header_field::EPOCH_NUMBER;
const CKB_HEADER_FIELD_EPOCH_START_BLOCK_NUMBER: u64 = ckb_abi::header_field::EPOCH_START_BLOCK_NUMBER;
const CKB_HEADER_FIELD_EPOCH_LENGTH: u64 = ckb_abi::header_field::EPOCH_LENGTH;
const CKB_DAO_HEADER_FIELD_ABSOLUTE_OFFSET: u64 = 160;
const CKB_DAO_HEADER_ACCUMULATED_RATE_ABSOLUTE_OFFSET: u64 = 160 + 8;
const CKB_DAO_TYPE_HASH_WORDS_LE: [i64; 4] = [-8442554211429484596, 7297449809414763189, -7890662964692133976, 6381290010727626424];
const CKB_INPUT_FIELD_OUT_POINT: u64 = ckb_abi::input_field::OUT_POINT;
const CKB_INPUT_FIELD_SINCE: u64 = ckb_abi::input_field::SINCE;
const CKB_SINCE_RELATIVE_FLAG: u64 = ckb_abi::since::RELATIVE_FLAG;
const CKB_SINCE_METRIC_TYPE_FLAG_MASK: u64 = ckb_abi::since::METRIC_TYPE_FLAG_MASK;
const CKB_SINCE_BLOCK_NUMBER_FLAG: u64 = ckb_abi::since::BLOCK_NUMBER_FLAG;
const CKB_SINCE_EPOCH_NUMBER_WITH_FRACTION_FLAG: u64 = ckb_abi::since::EPOCH_NUMBER_WITH_FRACTION_FLAG;
const CKB_SINCE_TIMESTAMP_FLAG: u64 = ckb_abi::since::TIMESTAMP_FLAG;
const CKB_SINCE_REMAIN_FLAGS_BITS: u64 = ckb_abi::since::REMAIN_FLAGS_BITS;
const CKB_SINCE_VALUE_MASK: u64 = ckb_abi::since::VALUE_MASK;
const CKB_SINCE_TIMESTAMP_BOUND: u64 = ckb_abi::since::TIMESTAMP_VALUE_BOUND;
const CKB_EPOCH_NUMBER_BOUND: u64 = ckb_abi::since::EPOCH_NUMBER_BOUND;
const CKB_EPOCH_FRACTION_BOUND: u64 = ckb_abi::since::EPOCH_FRACTION_BOUND;
const CKB_EPOCH_NUMBER_MASK: u64 = CKB_EPOCH_NUMBER_BOUND - 1;
const CKB_EPOCH_FRACTION_MASK: u64 = CKB_EPOCH_FRACTION_BOUND - 1;
const CKB_SOURCE_INPUT: u64 = ckb_abi::source::INPUT;
const CKB_SOURCE_OUTPUT: u64 = ckb_abi::source::OUTPUT;
const CKB_SOURCE_CELL_DEP: u64 = ckb_abi::source::CELL_DEP;
const CKB_SOURCE_HEADER_DEP: u64 = ckb_abi::source::HEADER_DEP;
const CKB_SOURCE_GROUP_FLAG: u64 = ckb_abi::source::GROUP_FLAG;
const CKB_SOURCE_GROUP_INPUT: u64 = ckb_abi::source::GROUP_INPUT;
const CKB_SOURCE_GROUP_OUTPUT: u64 = ckb_abi::source::GROUP_OUTPUT;

fn cell_source_value(source: IrCellSource) -> u64 {
    match source {
        IrCellSource::Input => CKB_SOURCE_INPUT,
        IrCellSource::Output => CKB_SOURCE_OUTPUT,
        IrCellSource::GroupInput => CKB_SOURCE_GROUP_INPUT,
        IrCellSource::GroupOutput => CKB_SOURCE_GROUP_OUTPUT,
        IrCellSource::CellDep => CKB_SOURCE_CELL_DEP,
    }
}
const CKB_SOURCE_VIEW_INPUT: u64 = ckb_abi::source_view::INPUT;
const CKB_SOURCE_VIEW_OUTPUT: u64 = ckb_abi::source_view::OUTPUT;
const CKB_SOURCE_VIEW_CELL_DEP: u64 = ckb_abi::source_view::CELL_DEP;
const CKB_SOURCE_VIEW_HEADER_DEP: u64 = ckb_abi::source_view::HEADER_DEP;
const CKB_SOURCE_VIEW_GROUP_INPUT: u64 = ckb_abi::source_view::GROUP_INPUT;
const CKB_SOURCE_VIEW_GROUP_OUTPUT: u64 = ckb_abi::source_view::GROUP_OUTPUT;
const CKB_SOURCE_VIEW_SHIFT: u64 = ckb_abi::source_view::SHIFT;
const CKB_ROLE_UNKNOWN: u64 = 0;
const CKB_CELL_FIELD_CAPACITY: u64 = ckb_abi::cell_field::CAPACITY;
const CKB_CELL_FIELD_LOCK: u64 = ckb_abi::cell_field::LOCK;
const CKB_CELL_FIELD_TYPE: u64 = ckb_abi::cell_field::TYPE;
const CKB_CELL_FIELD_LOCK_HASH: u64 = ckb_abi::cell_field::LOCK_HASH;
const CKB_CELL_FIELD_TYPE_HASH: u64 = ckb_abi::cell_field::TYPE_HASH;
const CKB_CELL_FIELD_DATA_HASH: u64 = ckb_abi::cell_field::DATA_HASH;
const CKB_CELL_FIELD_OCCUPIED_CAPACITY: u64 = ckb_abi::cell_field::OCCUPIED_CAPACITY;
const CKB_INDEX_OUT_OF_BOUND: u64 = ckb_abi::syscall_error::INDEX_OUT_OF_BOUND;
const CKB_ITEM_MISSING: u64 = ckb_abi::syscall_error::ITEM_MISSING;
const CKB_LENGTH_NOT_ENOUGH: u64 = ckb_abi::syscall_error::LENGTH_NOT_ENOUGH;
const RUNTIME_SCRATCH_BUFFER_SIZE: usize = 512;
const RUNTIME_SCRATCH_SLOT_SIZE: usize = 8 + RUNTIME_SCRATCH_BUFFER_SIZE;
const RUNTIME_SCRATCH_SIZE: usize = RUNTIME_SCRATCH_SLOT_SIZE * 2;
const RUNTIME_EXACT_READ_CACHE_CAPACITY: usize = 256;
const RUNTIME_EXACT_READ_CACHE_ENTRY_SIZE: usize = 56 + RUNTIME_EXACT_READ_CACHE_CAPACITY;
const RUNTIME_EXACT_READ_CACHE_WAYS: usize = 4;
// Base header: round-robin word, last-entry pointer and saved s11. The hot
// header additionally saves s10/s9/s8/s7/s6/s5 for a register-resident
// most-recent window.
const RUNTIME_EXACT_READ_CACHE_BASE_HEADER_SIZE: usize = 24;
const RUNTIME_EXACT_READ_CACHE_HOT_HEADER_SIZE: usize = 72;
// Static exact-read sites needed to amortize the hot header's entry/exit work.
// The ordinary four-way cache remains enabled below this threshold.
const RUNTIME_EXACT_READ_HOT_SITE_THRESHOLD: usize = 48;
const RUNTIME_EXPR_TEMP_SLOTS: usize = 16;
const RUNTIME_EXPR_TEMP_SIZE: usize = RUNTIME_EXPR_TEMP_SLOTS * 8;
const _: () = assert!(RUNTIME_EXPR_TEMP_SLOTS >= 4);
const RUNTIME_CELL_BUFFER_SIZE: usize = 512;
const RUNTIME_CELL_SLOT_SIZE: usize = 8 + RUNTIME_CELL_BUFFER_SIZE;
const RUNTIME_COLLECTION_BUFFER_SIZE: usize = 256;
const ENTRY_WITNESS_LABEL: &str = "_cellscript_entry";
const ENTRY_WITNESS_MAGIC: &[u8; 8] = ENTRY_WITNESS_ABI_MAGIC;
const ENTRY_WITNESS_HEADER_SIZE: usize = 8;
const ENTRY_WITNESS_SIZE_OFFSET: usize = 0;
const ENTRY_WITNESS_BUFFER_OFFSET: usize = 8;
const ENTRY_WITNESS_BUFFER_SIZE: usize = 4096;
const ENTRY_SCRIPT_SIZE_OFFSET: usize = ENTRY_WITNESS_BUFFER_OFFSET + ENTRY_WITNESS_BUFFER_SIZE;
const ENTRY_SCRIPT_ARGS_START_OFFSET: usize = ENTRY_SCRIPT_SIZE_OFFSET + 8;
const ENTRY_SCRIPT_ARGS_LEN_OFFSET: usize = ENTRY_SCRIPT_ARGS_START_OFFSET + 8;
const ENTRY_SCRIPT_ARGS_CURSOR_OFFSET: usize = ENTRY_SCRIPT_ARGS_LEN_OFFSET + 8;
const ENTRY_SCRIPT_BUFFER_OFFSET: usize = ENTRY_SCRIPT_ARGS_CURSOR_OFFSET + 8;
const ENTRY_SCRIPT_BUFFER_SIZE: usize = 1024;
// Reserved local-frame space keeps the entry trampoline's buffers isolated
// from its saved return address and preserves the v1 frame contract.
const ENTRY_WITNESS_RESERVED_FRAME_BYTES: usize = 208;
const ENTRY_WITNESS_FRAME_SIZE: usize =
    ENTRY_SCRIPT_BUFFER_OFFSET + ENTRY_SCRIPT_BUFFER_SIZE + ENTRY_WITNESS_RESERVED_FRAME_BYTES + core::mem::size_of::<u64>();
const ENTRY_WITNESS_RA_OFFSET: usize = ENTRY_WITNESS_FRAME_SIZE - 8;
const _: () = assert!(ENTRY_SCRIPT_BUFFER_OFFSET + ENTRY_SCRIPT_BUFFER_SIZE <= ENTRY_WITNESS_RA_OFFSET);
const _: () = assert!(ENTRY_WITNESS_FRAME_SIZE.is_multiple_of(16));

#[derive(Debug, Clone, Copy)]
struct RuntimeSyscallAbi {
    load_header: u64,
    load_header_by_field: u64,
    load_input_by_field: u64,
    load_witness: u64,
    load_script: u64,
    load_cell_by_field: u64,
    load_cell_data: u64,
    load_script_hash: u64,
    source_group_input: u64,
    source_header_dep: u64,
}

const CKB_RUNTIME_SYSCALL_ABI: RuntimeSyscallAbi = RuntimeSyscallAbi {
    load_header: CKB_LOAD_HEADER_SYSCALL_NUMBER,
    load_header_by_field: CKB_LOAD_HEADER_BY_FIELD_SYSCALL_NUMBER,
    load_input_by_field: CKB_LOAD_INPUT_BY_FIELD_SYSCALL_NUMBER,
    load_witness: CKB_LOAD_WITNESS_SYSCALL_NUMBER,
    load_script: CKB_LOAD_SCRIPT_SYSCALL_NUMBER,
    load_cell_by_field: CKB_LOAD_CELL_BY_FIELD_SYSCALL_NUMBER,
    load_cell_data: CKB_LOAD_CELL_DATA_SYSCALL_NUMBER,
    load_script_hash: CKB_LOAD_SCRIPT_HASH_SYSCALL_NUMBER,
    source_group_input: CKB_SOURCE_GROUP_FLAG | CKB_SOURCE_INPUT,
    source_header_dep: CKB_SOURCE_HEADER_DEP,
};

fn runtime_syscall_abi(profile: TargetProfile) -> RuntimeSyscallAbi {
    match profile {
        TargetProfile::Ckb => CKB_RUNTIME_SYSCALL_ABI,
    }
}

fn referenced_v014_runtime_helpers(ir: &IrModule) -> BTreeSet<String> {
    let mut helpers = BTreeSet::new();
    for item in &ir.items {
        let body = match item {
            IrItem::Action(action) => Some(&action.body),
            IrItem::PureFn(function) => Some(&function.body),
            IrItem::Lock(lock) => Some(&lock.body),
            IrItem::TypeDef(_) | IrItem::Invariant(_) => None,
        };
        let Some(body) = body else {
            continue;
        };
        for block in &body.blocks {
            for instruction in &block.instructions {
                let IrInstruction::Call { func, .. } = instruction else {
                    continue;
                };
                if is_v014_runtime_helper(func) {
                    helpers.insert(func.clone());
                }
            }
        }
    }
    helpers.extend(auto_lowered_aggregate_runtime_helpers_by_action(ir).into_values().flatten());
    if helpers.contains("__ckb_cell_unoccupied_capacity") {
        helpers.insert("__ckb_cell_capacity".to_string());
        helpers.insert("__ckb_cell_occupied_capacity".to_string());
    }
    if helpers.contains("__ckb_require_lock_type_metapoint_pairs")
        || helpers.contains("__ckb_require_type_lock_metapoint_pairs")
        || helpers.contains("__ckb_require_lock_type_metapoint_pairs_from_i32_data")
        || helpers.contains("__ckb_require_type_lock_metapoint_pairs_from_i32_data")
        || helpers.contains("__ckb_require_lock_type_metapoint_pairs_from_i32_data_filtered")
        || helpers.contains("__ckb_require_type_lock_metapoint_pairs_from_i32_data_filtered")
        || helpers.contains("__ckb_require_lock_match_master_out_point_pairs_from_data")
    {
        helpers.insert("__ckb_require_metapoint_relative".to_string());
    }
    if helpers.contains("__xudt_require_owner_mode_type_args_current_script") {
        helpers.insert("__xudt_require_owner_mode_type_args".to_string());
    }
    if helpers.contains("__novaseal_bip340_require_signature") || helpers.contains("__novaseal_bip340_require_signature_from_cell_dep")
    {
        helpers.insert("__ckb_pipe".to_string());
        helpers.insert("__ckb_pipe_write".to_string());
        helpers.insert("__ckb_close".to_string());
        helpers.insert("__ckb_spawn_with_fd1".to_string());
        helpers.insert("__ckb_wait".to_string());
    }
    helpers
}

fn auto_lowered_aggregate_runtime_helpers_by_action(ir: &IrModule) -> HashMap<String, BTreeSet<String>> {
    let invariants = ir
        .items
        .iter()
        .filter_map(|item| match item {
            IrItem::Invariant(invariant) => Some(invariant),
            _ => None,
        })
        .collect::<Vec<_>>();
    let mut by_action = HashMap::new();
    for item in &ir.items {
        let IrItem::Action(action) = item else {
            continue;
        };
        let helpers = invariants
            .iter()
            .flat_map(|invariant| {
                invariant
                    .aggregates
                    .iter()
                    .filter_map(|aggregate| auto_lowered_aggregate_runtime_helper_for_action(invariant, aggregate, action))
            })
            .map(str::to_string)
            .collect::<BTreeSet<_>>();
        if !helpers.is_empty() {
            by_action.insert(action.name.clone(), helpers);
        }
    }
    by_action
}

fn auto_lowered_aggregate_runtime_helper_for_action(
    invariant: &IrInvariant,
    aggregate: &IrAggregateInvariant,
    action: &IrAction,
) -> Option<&'static str> {
    let type_name = xudt_group_amount_conservation_type(invariant, aggregate)?;
    if body_contains_runtime_helper(&action.body, XUDT_GROUP_AMOUNT_CONSERVED_CODEGEN_HELPER) {
        return None;
    }
    action_has_group_amount_conservation_evidence(action, type_name).then_some(XUDT_GROUP_AMOUNT_CONSERVED_CODEGEN_HELPER)
}

fn is_v014_runtime_helper(func: &str) -> bool {
    matches!(
        func,
        "__ckb_spawn"
            | "__ckb_exec_cell_dep_u8_args"
            | "__ckb_exec_cell_dep_hex4"
            | "__ckb_spawn_wait_cell_dep_hex4"
            | "__ckb_wait"
            | "__ckb_process_id"
            | "__ckb_pipe"
            | "__ckb_pipe_write"
            | "__ckb_pipe_read"
            | "__ckb_inherited_fd"
            | "__ckb_close"
            | "__ckb_spawn_with_fd1"
            | "__ckb_source_input"
            | "__ckb_source_output"
            | "__ckb_source_cell_dep"
            | "__ckb_source_header_dep"
            | "__ckb_source_group_input"
            | "__ckb_source_group_output"
            | "__ckb_since_epoch_absolute"
            | "__ckb_since_epoch_relative"
            | "__ckb_since_block_absolute"
            | "__ckb_since_block_relative"
            | "__ckb_since_timestamp_absolute"
            | "__ckb_since_timestamp_relative"
            | "__ckb_since_decode"
            | "__ckb_since_from_raw_checked"
            | "__ckb_since_as_absolute_block"
            | "__ckb_since_as_relative_block"
            | "__ckb_since_as_absolute_epoch"
            | "__ckb_since_as_relative_epoch"
            | "__ckb_since_as_absolute_timestamp"
            | "__ckb_since_as_relative_timestamp"
            | "__ckb_since_is_relative"
            | "__ckb_since_is_disabled"
            | "__ckb_since_metric"
            | "__ckb_since_value"
            | "__ckb_since_to_raw"
            | "__ckb_epoch_number_to_u64"
            | "__ckb_block_number_to_u64"
            | "__ckb_epoch_length_to_u64"
            | "__ckb_current_role"
            | "__ckb_current_script_hash"
            | "__ckb_cell_capacity"
            | "__ckb_cell_occupied_capacity"
            | "__ckb_cell_unoccupied_capacity"
            | "__ckb_cell_output_index"
            | "__ckb_input_out_point_index"
            | "__ckb_input_out_point_tx_hash_low"
            | "__ckb_input_out_point_tx_hash"
            | "__ckb_require_input_out_point_tx_hash"
            | "__ckb_require_input_out_point"
            | "__ckb_require_metapoint_relative"
            | "__ckb_require_lock_type_metapoint_pairs"
            | "__ckb_require_type_lock_metapoint_pairs"
            | "__ckb_require_lock_type_metapoint_pairs_from_i32_data"
            | "__ckb_require_type_lock_metapoint_pairs_from_i32_data"
            | "__ckb_require_lock_type_metapoint_pairs_from_i32_data_filtered"
            | "__ckb_require_type_lock_metapoint_pairs_from_i32_data_filtered"
            | "__ckb_require_lock_match_master_out_point_pairs_from_data"
            | "__ckb_cell_lock_hash_low"
            | "__ckb_cell_type_hash_low"
            | "__ckb_cell_lock_hash"
            | "__ckb_cell_type_hash"
            | "__ckb_cell_data_hash_field"
            | "__ckb_cell_data_hash"
            | "__ckb_cell_data_hash_at"
            | "__ckb_cell_data_blake2b_span"
            | "__ckb_witness_blake2b_span"
            | "__ckb_raw_transaction_hash_without_cell_deps"
            | "__ckb_transaction_blake2b_gather"
            | "__ckb_witness_blake2b_select_chunks"
            | "__ckb_transaction_u32_le"
            | "__ckb_witness_bytes32"
            | "__ckb_cell_lock_code_hash"
            | "__ckb_cell_type_code_hash"
            | "__ckb_cell_lock_hash_type"
            | "__ckb_cell_type_hash_type"
            | "__ckb_cell_lock_args_empty"
            | "__ckb_cell_type_args_empty"
            | "__ckb_cell_lock_args_hash"
            | "__ckb_cell_type_args_hash"
            | "__ckb_require_cell_lock_hash"
            | "__ckb_require_cell_type_hash"
            | "__ckb_require_cell_data_hash"
            | "__ckb_require_bounded_cell_dep_data_hash"
            | "__ckb_require_current_script_args_empty"
            | "__ckb_require_cell_lock_args_empty"
            | "__ckb_require_cell_type_args_empty"
            | "__ckb_require_cell_lock_args_hash"
            | "__ckb_require_cell_type_args_hash"
            | "__ckb_require_cell_lock_args_exact"
            | "__ckb_require_cell_type_args_exact"
            | "__ckb_require_cell_lock_args_prefix_hash"
            | "__ckb_require_cell_type_args_prefix_hash"
            | "__ckb_require_cell_lock_args_suffix_hash"
            | "__ckb_require_cell_type_args_suffix_hash"
            | "__ckb_require_cell_lock_script_hash_type"
            | "__ckb_require_cell_type_script_hash_type"
            | "__c256_require_u128_product_lte"
            | "__c256_require_u128_product_eq"
            | "__c256_require_u128_sum2_products_lte"
            | "__c256_require_u128_sum2_products_eq"
            | "__ckb_cell_data_size"
            | "__ckb_cell_data_equal"
            | "__ckb_source_bytes_equal"
            | "__ckb_source_bytes_equal_memory"
            | "__ckb_source_bytes_zero"
            | "__ckb_cell_count"
            | "__ckb_cell_has_type"
            | "__ckb_cell_data_u8"
            | "__ckb_cell_lock_size"
            | "__ckb_cell_type_size"
            | "__ckb_cell_lock_u8"
            | "__ckb_cell_type_u8"
            | "__ckb_input_since_at"
            | "__ckb_cell_data_u32_le"
            | "__ckb_cell_data_u64_le"
            | "__dao_accumulated_rate"
            | "__dao_input_accumulated_rate"
            | "__dao_has_dao_type"
            | "__dao_is_deposit_data"
            | "__dao_is_withdrawal_request_data"
            | "__dao_require_header_dep_for_input"
            | "__dao_require_input_since_at_least"
            | "__dao_require_input_relative_epoch_since_at_least"
            | "__xudt_amount_low"
            | "__xudt_amount_high"
            | "__xudt_owner_mode_input_type_hash"
            | "__xudt_require_owner_mode_input_type"
            | "__xudt_require_owner_mode_type_args"
            | "__xudt_require_owner_mode_type_args_current_script"
            | "__cellscript_require_fungible_type_group_v1"
            | "__xudt_require_group_amount_conserved"
            | "__xudt_require_group_amount_minted"
            | "__xudt_require_group_amount_burned"
            | "__ckb_witness_raw"
            | "__ckb_witness_lock"
            | "__ckb_witness_input_type"
            | "__ckb_witness_output_type"
            | "__ckb_witness_size"
            | "__ckb_witness_count"
            | "__ckb_witness_u8"
            | "__ckb_witness_u32_le"
            | "__ckb_witness_u64_le"
            | "__ckb_require_witness_size_at_least"
            | "__ckb_sighash_all"
            | "__ckb_require_maturity"
            | "__ckb_require_time"
            | "__ckb_require_epoch_after"
            | "__ckb_require_epoch_relative"
            | "__ckb_occupied_capacity"
            | "__ckb_hash_chain"
            | "__ckb_hash_pair"
            | "__ckb_hash_blake2b"
            | "__ckb_hash_blake2b_var"
            | "__ckb_hash_blake2b_packed"
            | "__ckb_hash_data_packed"
            | "__ckb_hash_sha256"
            | "__ckb_hash_sha256d"
            | "__ckb_hash_sha256_pair"
            | "__ckb_hash_sha256d_pair"
            | "__ckb_require_sha256d_merkle_root"
            | "__novaseal_bip340_require_signature"
            | "__novaseal_bip340_require_signature_from_cell_dep"
    )
}

fn is_cached_exact_read_helper(func: &str) -> bool {
    matches!(
        func,
        "__ckb_cell_data_u8"
            | "__ckb_cell_data_u32_le"
            | "__ckb_cell_data_u64_le"
            | "__ckb_witness_u8"
            | "__ckb_witness_u32_le"
            | "__ckb_witness_u64_le"
            | "__ckb_cell_lock_u8"
            | "__ckb_cell_type_u8"
    )
}

fn is_source_view_helper(func: &str) -> bool {
    matches!(
        func,
        "__ckb_source_input"
            | "__ckb_source_output"
            | "__ckb_source_cell_dep"
            | "__ckb_source_header_dep"
            | "__ckb_source_group_input"
            | "__ckb_source_group_output"
    )
}

fn is_terminal_scalar_runtime_helper(func: &str) -> bool {
    is_cached_exact_read_helper(func)
        || is_source_view_helper(func)
        || matches!(
            func,
            "__ckb_witness_count"
                | "__ckb_witness_size"
                | "__ckb_cell_count"
                | "__ckb_cell_has_type"
                | "__ckb_cell_data_size"
                | "__ckb_cell_lock_size"
                | "__ckb_cell_type_size"
        )
}

fn is_ckb_fixed_hash_helper(func: &str) -> bool {
    matches!(
        func,
        "__ckb_hash_chain"
            | "__ckb_hash_pair"
            | "__ckb_hash_blake2b"
            | "__ckb_hash_blake2b_var"
            | "__ckb_hash_blake2b_packed"
            | "__ckb_hash_data_packed"
            | "__ckb_hash_sha256"
            | "__ckb_hash_sha256d"
            | "__ckb_hash_sha256_pair"
            | "__ckb_hash_sha256d_pair"
    )
}

#[derive(Debug, Clone)]
struct SchemaFieldLayout {
    index: usize,
    offset: usize,
    ty: IrType,
    fixed_size: Option<usize>,
    fixed_enum_size: Option<usize>,
}

#[derive(Debug, Clone)]
struct SchemaFieldValueSource {
    obj_var_id: usize,
    type_name: String,
    field: String,
    layout: SchemaFieldLayout,
}

#[derive(Debug, Clone)]
struct AggregatePointerSource {
    ty: IrType,
}

#[derive(Debug, Clone)]
enum ExpectedFixedByteSource {
    SchemaField(SchemaFieldValueSource),
    Const(Vec<u8>),
    StackSlot { var_id: usize, width: usize },
    PointerBytes { var_id: usize, width: usize },
    ParamBytes { var_id: usize, size_offset: usize, width: usize },
    LoadedBytes { var_id: usize, size_offset: usize, width: usize },
}

#[derive(Debug, Clone, Copy)]
enum ScriptHashFieldRead {
    CodeHash,
    Args32,
}

#[derive(Debug, Clone, Copy)]
enum ScriptScalarFieldRead {
    HashType,
    ArgsEmpty,
}

#[derive(Debug, Clone, Copy)]
enum ScriptArgsHashRequirementMode {
    Exact32,
    Prefix32,
    Suffix32,
}

#[derive(Debug, Clone, Copy)]
enum SourcePointer {
    LoadedStackPointer { var_id: usize, offset: usize },
    StackAddress { offset: usize },
}

fn fixed_scalar_width(ty: &IrType, fixed_size: Option<usize>) -> Option<usize> {
    match (ty, fixed_size) {
        (IrType::Bool | IrType::U8, Some(1)) => Some(1),
        (IrType::U16, Some(2)) => Some(2),
        (IrType::U32, Some(4)) => Some(4),
        (IrType::I32, Some(4)) => Some(4),
        (IrType::U64, Some(8)) => Some(8),
        (IrType::Named(name), Some(8)) if is_ckb_temporal_scalar_name(name) => Some(8),
        _ => None,
    }
}

fn is_ckb_temporal_scalar_name(name: &str) -> bool {
    matches!(
        name,
        "EpochNumber"
            | "BlockNumber"
            | "EpochLength"
            | "EncodedSince"
            | "DecodedSince"
            | "AbsoluteBlockSince"
            | "AbsoluteEpochSince"
            | "AbsoluteTimestampSince"
            | "RelativeBlockSince"
            | "RelativeEpochSince"
            | "RelativeTimestampSince"
    ) || name.starts_with("Since<Absolute, ")
        || name.starts_with("Since<Relative, ")
}

fn is_ckb_temporal_scalar_ir_type(ty: &IrType) -> bool {
    matches!(ty, IrType::Named(name) if is_ckb_temporal_scalar_name(name))
}

fn is_fixed_scalar_ir_type(ty: &IrType) -> bool {
    matches!(ty, IrType::Bool | IrType::U8 | IrType::U16 | IrType::U32 | IrType::I32 | IrType::U64)
        || is_ckb_temporal_scalar_ir_type(ty)
}

fn identity_policy_label(identity: &IrIdentityPolicy) -> String {
    match identity {
        IrIdentityPolicy::None => "none".to_string(),
        IrIdentityPolicy::CkbTypeId => "ckb_type_id".to_string(),
        IrIdentityPolicy::Field(path) => format!("field({})", path),
        IrIdentityPolicy::ScriptArgs => "script_args".to_string(),
        IrIdentityPolicy::SingletonType => "singleton_type".to_string(),
    }
}

/// Fixed-width types that fit in a single RISC-V 64-bit register (≤8 bytes).
/// Used by transition formula verification which needs scalar add/sub.
fn fixed_register_width(ty: &IrType, fixed_size: Option<usize>) -> Option<usize> {
    let w = fixed_scalar_width(ty, fixed_size)?;
    (w <= 8).then_some(w)
}

fn fixed_byte_width(ty: &IrType, fixed_size: Option<usize>) -> Option<usize> {
    if let Some(width) = fixed_scalar_width(ty, fixed_size) {
        return Some(width);
    }
    match (ty, fixed_size) {
        (IrType::Address | IrType::Hash, Some(32)) => Some(32),
        (IrType::U128, Some(16)) => Some(16),
        (IrType::Array(inner, len), Some(size)) if matches!(inner.as_ref(), IrType::U8) && *len == size => Some(size),
        (IrType::Ref(inner) | IrType::MutRef(inner), _) => fixed_byte_width(inner, type_static_length(inner)),
        _ => None,
    }
}

fn molecule_vector_element_fixed_width(
    ty: &IrType,
    type_fixed_sizes: &HashMap<String, usize>,
    enum_fixed_sizes: &HashMap<String, usize>,
) -> Option<usize> {
    let IrType::Named(name) = ty else {
        return None;
    };
    if name == "String" {
        return Some(1);
    }
    let inner = name.strip_prefix("Vec<")?.strip_suffix('>')?;
    molecule_inline_type_fixed_width(inner, type_fixed_sizes, enum_fixed_sizes)
}

fn molecule_inline_type_fixed_width(
    ty: &str,
    type_fixed_sizes: &HashMap<String, usize>,
    enum_fixed_sizes: &HashMap<String, usize>,
) -> Option<usize> {
    match ty.trim() {
        "bool" | "u8" => Some(1),
        "u16" => Some(2),
        "u32" => Some(4),
        "i32" => Some(4),
        "u64" => Some(8),
        "u128" => Some(16),
        "Address" | "Hash" => Some(32),
        other => type_fixed_sizes.get(other).copied().or_else(|| enum_fixed_sizes.get(other).copied()),
    }
}

fn layout_fixed_scalar_width(layout: &SchemaFieldLayout) -> Option<usize> {
    fixed_scalar_width(&layout.ty, layout.fixed_size).or_else(|| (layout.fixed_enum_size == Some(1)).then_some(1))
}

fn layout_fixed_byte_width(layout: &SchemaFieldLayout) -> Option<usize> {
    fixed_byte_width(&layout.ty, layout.fixed_size).or(layout.fixed_enum_size)
}

fn layout_flow_state_width(layout: &SchemaFieldLayout) -> Option<usize> {
    layout_fixed_scalar_width(layout)
}

fn type_static_length(ty: &IrType) -> Option<usize> {
    match ty {
        IrType::Bool | IrType::U8 => Some(1),
        IrType::U16 => Some(2),
        IrType::U32 => Some(4),
        IrType::I32 => Some(4),
        IrType::U64 => Some(8),
        IrType::U128 => Some(16),
        IrType::Address | IrType::Hash => Some(32),
        IrType::Array(inner, len) => type_static_length(inner).map(|inner_len| inner_len * len),
        IrType::Tuple(items) => items.iter().try_fold(0usize, |acc, item| type_static_length(item).map(|len| acc + len)),
        IrType::Unit => Some(0),
        IrType::Ref(inner) | IrType::MutRef(inner) => type_static_length(inner),
        IrType::Named(name) if is_ckb_temporal_scalar_name(name) => Some(8),
        IrType::Named(_) => None,
    }
}

fn operand_fixed_byte_width(operand: &IrOperand) -> Option<usize> {
    let ty = match operand {
        IrOperand::Const(IrConst::Address(_)) | IrOperand::Const(IrConst::Hash(_)) => return Some(32),
        IrOperand::Const(IrConst::Array(values)) => return Some(values.len()),
        IrOperand::Const(IrConst::U128(_)) => return Some(16),
        IrOperand::Var(var) => &var.ty,
        _ => return None,
    };
    match ty {
        IrType::Address | IrType::Hash => Some(32),
        IrType::U128 => Some(16),
        IrType::Array(_, _) | IrType::Tuple(_) => type_static_length(ty),
        _ => None,
    }
}

fn constructed_byte_vector_part_width(operand: &IrOperand) -> Option<usize> {
    operand_fixed_byte_width(operand).or_else(|| match operand {
        IrOperand::Var(var) => fixed_scalar_width(&var.ty, type_static_length(&var.ty)),
        IrOperand::Const(IrConst::Bool(_)) | IrOperand::Const(IrConst::U8(_)) => Some(1),
        IrOperand::Const(IrConst::U16(_)) => Some(2),
        IrOperand::Const(IrConst::U32(_)) => Some(4),
        IrOperand::Const(IrConst::U64(_)) => Some(8),
        _ => None,
    })
}

fn fixed_scalar_operand_width(operand: &IrOperand) -> Option<usize> {
    match operand {
        IrOperand::Var(var) => fixed_scalar_width(&var.ty, type_static_length(&var.ty)),
        IrOperand::Const(IrConst::Bool(_)) | IrOperand::Const(IrConst::U8(_)) => Some(1),
        IrOperand::Const(IrConst::U16(_)) => Some(2),
        IrOperand::Const(IrConst::U32(_)) => Some(4),
        IrOperand::Const(IrConst::U64(_)) => Some(8),
        _ => None,
    }
}

fn simple_scalar_operand(operand: &IrOperand) -> bool {
    match operand {
        IrOperand::Const(IrConst::Bool(_) | IrConst::U8(_) | IrConst::U16(_) | IrConst::U32(_) | IrConst::U64(_)) => true,
        IrOperand::Var(var) => {
            matches!(var.ty, IrType::Bool | IrType::U8 | IrType::U16 | IrType::U32 | IrType::I32 | IrType::U64)
                || is_ckb_temporal_scalar_ir_type(&var.ty)
        }
        _ => false,
    }
}

fn ckb_epoch_since_operand_type(operand: &IrOperand) -> Option<&str> {
    let IrOperand::Var(var) = operand else {
        return None;
    };
    let IrType::Named(name) = &var.ty else {
        return None;
    };
    matches!(name.as_str(), "AbsoluteEpochSince" | "RelativeEpochSince").then_some(name)
}

fn matching_ckb_epoch_since_operands(left: &IrOperand, right: &IrOperand) -> bool {
    let (Some(left), Some(right)) = (ckb_epoch_since_operand_type(left), ckb_epoch_since_operand_type(right)) else {
        return false;
    };
    left == right
}

fn body_var_use_count(body: &IrBody, var_id: usize) -> usize {
    body.blocks
        .iter()
        .map(|block| {
            block.instructions.iter().map(|instruction| instruction_var_use_count(instruction, var_id)).sum::<usize>()
                + terminator_var_use_count(&block.terminator, var_id)
        })
        .sum()
}

fn operand_var_use_count(operand: &IrOperand, var_id: usize) -> usize {
    usize::from(matches!(operand, IrOperand::Var(var) if var.id == var_id))
}

fn operands_var_use_count<'a>(operands: impl IntoIterator<Item = &'a IrOperand>, var_id: usize) -> usize {
    operands.into_iter().map(|operand| operand_var_use_count(operand, var_id)).sum()
}

fn create_pattern_var_use_count(pattern: &CreatePattern, var_id: usize) -> usize {
    operands_var_use_count(pattern.fields.iter().map(|(_, operand)| operand), var_id)
        + pattern.lock.as_ref().map_or(0, |operand| operand_var_use_count(operand, var_id))
}

fn instruction_var_use_count(instruction: &IrInstruction, var_id: usize) -> usize {
    match instruction {
        IrInstruction::LoadConst { .. } | IrInstruction::LoadVar { .. } | IrInstruction::ReadRef { .. } => 0,
        IrInstruction::StoreVar { src, .. }
        | IrInstruction::Unary { operand: src, .. }
        | IrInstruction::FieldAccess { obj: src, .. }
        | IrInstruction::Length { operand: src, .. }
        | IrInstruction::TypeHash { operand: src, .. }
        | IrInstruction::CollectionCapacity { collection: src, .. }
        | IrInstruction::CollectionClear { collection: src }
        | IrInstruction::CollectionReverse { collection: src }
        | IrInstruction::CollectionPop { collection: src, .. }
        | IrInstruction::EnumTag { operand: src, .. }
        | IrInstruction::EnumPayload { operand: src, .. }
        | IrInstruction::Consume { operand: src }
        | IrInstruction::Destroy { operand: src, .. }
        | IrInstruction::Claim { receipt: src, .. }
        | IrInstruction::Settle { operand: src, .. }
        | IrInstruction::Move { src, .. } => operand_var_use_count(src, var_id),
        IrInstruction::Binary { left, right, .. }
        | IrInstruction::Index { arr: left, idx: right, .. }
        | IrInstruction::CollectionPush { collection: left, value: right }
        | IrInstruction::CollectionExtend { collection: left, slice: right }
        | IrInstruction::CollectionContains { collection: left, value: right, .. }
        | IrInstruction::CollectionRemove { collection: left, index: right, .. }
        | IrInstruction::CollectionInsert { collection: left, index: right, .. }
        | IrInstruction::CollectionSet { collection: left, index: right, .. }
        | IrInstruction::CollectionTruncate { collection: left, len: right }
        | IrInstruction::CellMetadataEquality { left, right, .. } => {
            operand_var_use_count(left, var_id) + operand_var_use_count(right, var_id)
        }
        IrInstruction::CollectionNew { capacity, .. } => capacity.as_ref().map_or(0, |operand| operand_var_use_count(operand, var_id)),
        IrInstruction::CollectionSwap { collection, left, right } => {
            operand_var_use_count(collection, var_id) + operand_var_use_count(left, var_id) + operand_var_use_count(right, var_id)
        }
        IrInstruction::BoundedCellLoad { index, .. } => operand_var_use_count(index, var_id),
        IrInstruction::BoundedPlanLoad { plan, index, .. } => {
            operand_var_use_count(plan, var_id) + operand_var_use_count(index, var_id)
        }
        IrInstruction::BoundedOutputVerify { index, pattern, .. } => {
            operand_var_use_count(index, var_id) + create_pattern_var_use_count(pattern, var_id)
        }
        IrInstruction::Call { args, .. } => operands_var_use_count(args, var_id),
        IrInstruction::Tuple { fields, .. } | IrInstruction::EnumConstruct { fields, .. } => operands_var_use_count(fields, var_id),
        IrInstruction::Create { pattern, .. } | IrInstruction::CreateUnique { pattern, .. } => {
            create_pattern_var_use_count(pattern, var_id)
        }
        IrInstruction::Transfer { operand, to, .. } => operand_var_use_count(operand, var_id) + operand_var_use_count(to, var_id),
        IrInstruction::ReplaceUnique { operand, pattern, .. } => {
            operand_var_use_count(operand, var_id) + create_pattern_var_use_count(pattern, var_id)
        }
        IrInstruction::BoundedOutputEnd { index } => operand_var_use_count(index, var_id),
    }
}

fn terminator_var_use_count(terminator: &IrTerminator, var_id: usize) -> usize {
    match terminator {
        IrTerminator::Return(Some(operand)) | IrTerminator::Branch { cond: operand, .. } => operand_var_use_count(operand, var_id),
        IrTerminator::Return(None) | IrTerminator::Jump(_) => 0,
    }
}

fn operand_is_signed_i32(operand: &IrOperand) -> bool {
    matches!(operand, IrOperand::Var(var) if var.ty == IrType::I32)
}

fn binary_operands_signed_i32(left: &IrOperand, right: &IrOperand) -> bool {
    operand_is_signed_i32(left) || operand_is_signed_i32(right)
}

fn collect_pure_const_returns(ir: &IrModule) -> HashMap<String, IrConst> {
    ir.items
        .iter()
        .filter_map(|item| {
            let IrItem::PureFn(function) = item else {
                return None;
            };
            pure_const_return(&function.body).map(|value| (function.name.clone(), value))
        })
        .collect()
}

fn pure_const_return(body: &IrBody) -> Option<IrConst> {
    let [block] = body.blocks.as_slice() else {
        return None;
    };
    if block.runtime_error.is_some() {
        return None;
    }
    match (&block.instructions[..], &block.terminator) {
        ([], IrTerminator::Return(Some(IrOperand::Const(value)))) => Some(value.clone()),
        ([IrInstruction::LoadConst { dest, value }], IrTerminator::Return(Some(IrOperand::Var(var)))) if dest.id == var.id => {
            Some(value.clone())
        }
        _ => None,
    }
}

fn fixed_byte_pointer_param_width(ty: &IrType) -> Option<usize> {
    fixed_byte_width(ty, type_static_length(ty)).filter(|width| *width > 8)
}

fn fixed_aggregate_pointer_param_width(ty: &IrType) -> Option<usize> {
    match ty {
        IrType::Array(_, _) | IrType::Tuple(_) => type_static_length(ty).filter(|width| *width > 8),
        _ => None,
    }
}

fn fixed_byte_const_bytes(value: &IrConst) -> Option<Vec<u8>> {
    match value {
        IrConst::Address(bytes) | IrConst::Hash(bytes) => Some(bytes.to_vec()),
        IrConst::U128(value) => Some(value.to_le_bytes().to_vec()),
        IrConst::Array(values) => values
            .iter()
            .map(|value| match value {
                IrConst::U8(byte) => Some(*byte),
                _ => None,
            })
            .collect(),
        _ => None,
    }
}

fn fixed_scalar_const_value(value: &IrConst) -> Option<u64> {
    match value {
        IrConst::Bool(value) => Some(u64::from(*value)),
        IrConst::U8(value) => Some((*value).into()),
        IrConst::U16(value) => Some((*value).into()),
        IrConst::U32(value) => Some((*value).into()),
        IrConst::U64(value) => Some(*value),
        _ => None,
    }
}

fn const_usize_operand(operand: &IrOperand) -> Option<usize> {
    match operand {
        IrOperand::Const(IrConst::U8(value)) => Some((*value).into()),
        IrOperand::Const(IrConst::U16(value)) => Some((*value).into()),
        IrOperand::Const(IrConst::U32(value)) => Some(*value as usize),
        IrOperand::Const(IrConst::U64(value)) => usize::try_from(*value).ok(),
        _ => None,
    }
}

fn aggregate_type_label(ty: &IrType) -> String {
    match ty {
        IrType::Tuple(_) => "tuple".to_string(),
        IrType::Array(_, len) => format!("array{}", len),
        IrType::Address => "Address".to_string(),
        IrType::Hash => "Hash".to_string(),
        other => format!("{:?}", other),
    }
}

fn aggregate_field_layout(ty: &IrType, field: &str) -> Option<SchemaFieldLayout> {
    match ty {
        IrType::Tuple(items) => {
            let index = field.parse::<usize>().ok()?;
            let field_ty = items.get(index)?.clone();
            let offset = items.iter().take(index).try_fold(0usize, |acc, item| type_static_length(item).map(|size| acc + size))?;
            let fixed_size = type_static_length(&field_ty);
            Some(SchemaFieldLayout { index, offset, ty: field_ty, fixed_size, fixed_enum_size: None })
        }
        IrType::Address | IrType::Hash if field == "0" => Some(SchemaFieldLayout {
            index: 0,
            offset: 0,
            ty: IrType::Array(Box::new(IrType::U8), 32),
            fixed_size: Some(32),
            fixed_enum_size: None,
        }),
        IrType::Array(inner, len) => {
            let index = field.parse::<usize>().ok()?;
            if index >= *len {
                return None;
            }
            let field_ty = inner.as_ref().clone();
            let width = type_static_length(&field_ty)?;
            Some(SchemaFieldLayout {
                index,
                offset: index.checked_mul(width)?,
                ty: field_ty,
                fixed_size: Some(width),
                fixed_enum_size: None,
            })
        }
        _ => None,
    }
}

fn tuple_return_field_type(ty: &IrType, field: &str) -> Option<IrType> {
    let IrType::Tuple(items) = ty else {
        return None;
    };
    let index = field.parse::<usize>().ok()?;
    (index < 8).then(|| items.get(index).cloned()).flatten()
}

fn abi_arg_label(index: usize) -> String {
    if index < 8 {
        format!("a{}", index)
    } else {
        format!("stack+{}", (index - 8) * 8)
    }
}

fn call_abi_arg_count(abi: Option<&CallableAbi>, args: &[IrOperand]) -> usize {
    let mut count = 0usize;
    for (arg_index, _) in args.iter().enumerate() {
        if let Some(abi) = abi
            && let Some(param) = abi.params.get(arg_index)
        {
            count += call_param_abi_arg_count(param, abi.type_hash_param_indices.contains(&arg_index));
            continue;
        }
        count += 1;
    }
    count
}

fn entry_abi_arg_count(params: &[IrParam], abi: Option<&CallableAbi>) -> usize {
    let type_hash_param_indices = abi.map(|abi| &abi.type_hash_param_indices);
    params
        .iter()
        .enumerate()
        .map(|(index, param)| call_param_abi_arg_count(param, type_hash_param_indices.is_some_and(|indices| indices.contains(&index))))
        .sum()
}

fn align_stack_arg_bytes(bytes: usize) -> usize {
    if bytes == 0 {
        0
    } else {
        bytes.next_multiple_of(16)
    }
}

fn call_param_abi_arg_count(param: &IrParam, needs_type_hash: bool) -> usize {
    if is_ckb_temporal_scalar_ir_type(&param.ty) {
        return 1;
    }
    if named_type_name(&param.ty).is_some() {
        return 2 + usize::from(needs_type_hash) * 2;
    }
    if fixed_byte_pointer_param_width(&param.ty).or_else(|| fixed_aggregate_pointer_param_width(&param.ty)).is_some() {
        return 2;
    }
    1
}

#[derive(Debug, Clone)]
enum PreludeU64OperandSource {
    Const(u64),
    ParamVar(usize),
    StackVar(usize),
    Field(SchemaFieldValueSource),
    Expr(Box<PreludeU64ValueSource>),
}

#[derive(Debug, Clone)]
enum PreludeU64ValueSource {
    Const(u64),
    ParamVar(usize),
    StackVar(usize),
    Field(SchemaFieldValueSource),
    Binary { op: BinaryOp, left: Box<PreludeU64ValueSource>, right: PreludeU64OperandSource },
    Min { left: Box<PreludeU64ValueSource>, right: PreludeU64OperandSource },
}

#[derive(Debug, Clone)]
struct CallableAbi {
    params: Vec<IrParam>,
    type_hash_param_indices: BTreeSet<usize>,
    runtime_bound_param_indices: BTreeSet<usize>,
    bounded_plan_param_indices: BTreeSet<usize>,
}

#[derive(Debug, Clone, Copy)]
enum CallLengthKind {
    Schema,
    FixedBytes,
}

#[derive(Debug, Clone, Copy)]
struct EntryWitnessPayloadArg {
    width: usize,
    schema_dynamic: bool,
    unsupported: bool,
}

#[derive(Debug, Clone)]
pub struct CodegenOptions {
    pub opt_level: u8,
    pub debug: bool,
    /// Artifact target profile. CKB selects the CKB syscall/source ABI.
    pub target_profile: TargetProfile,
}

impl Default for CodegenOptions {
    fn default() -> Self {
        Self { opt_level: 0, debug: false, target_profile: TargetProfile::Ckb }
    }
}

pub struct CodeGenerator {
    options: CodegenOptions,
    assembly: Vec<String>,
    current_function: Option<String>,
    current_function_owns_exact_read_cache: bool,
    module_uses_exact_read_cache: bool,
    module_uses_exact_read_hot_cache: bool,
    frame_size: usize,
    next_virtual_output: usize,
    /// Stack-frame start offset for runtime collection buffers.
    collection_region_start: usize,
    /// Runtime collection buffer allocator for the current function.
    next_collection_slot: usize,
    /// Named schema field layouts, keyed by type name then field name.
    type_layouts: HashMap<String, HashMap<String, SchemaFieldLayout>>,
    /// Fieldless enum storage widths, keyed by enum name.
    enum_fixed_sizes: HashMap<String, usize>,
    /// Canonical tagged-union layouts for concrete payload enums.
    enum_layouts: HashMap<String, IrEnumLayout>,
    /// Fixed encoded size of named schemas when all fields have fixed-width layouts.
    type_fixed_sizes: HashMap<String, usize>,
    /// Named types declared as receipts.
    receipt_type_names: BTreeSet<String>,
    /// Named types that are transaction cell-backed values.
    cell_type_names: BTreeSet<String>,
    /// State names for schemas that declared flow policy.
    flow_states: HashMap<String, Vec<String>>,
    /// Flow field name keyed by schema type.
    flow_state_fields: HashMap<String, String>,
    /// Declared flow/flow transition graph keyed by schema type.
    flow_rules: HashMap<String, Vec<IrFlowRule>>,
    /// Action-specific state edges for the function currently being emitted.
    current_state_transition_edges: Vec<IrStateTransitionEdge>,
    /// Runtime helpers emitted in action preludes by compiler-lowered aggregate invariants.
    auto_aggregate_runtime_helpers_by_action: HashMap<String, BTreeSet<String>>,
    /// ABI summaries for locally emitted actions/functions/locks.
    callable_abis: HashMap<String, CallableAbi>,
    /// Function parameters whose slot contains a pointer to encoded schema bytes.
    schema_pointer_vars: BTreeSet<usize>,
    /// Function parameter slots available before the prelude summaries run.
    param_vars: BTreeSet<usize>,
    /// Schema pointer slots backed by a VM-loaded cell buffer size word.
    schema_pointer_size_offsets: HashMap<usize, usize>,
    /// Exact schema sizes established by unconditional entry-prelude loads.
    /// These facts dominate every emitted IR block until the size slot is
    /// reused by another syscall.
    dominant_schema_exact_sizes: HashMap<usize, usize>,
    /// Exact schema sizes established within the block currently being
    /// emitted. They are cleared at every block boundary.
    block_schema_exact_sizes: HashMap<usize, usize>,
    /// Minimum schema sizes established within the block currently being
    /// emitted. They are cleared at every block boundary.
    block_schema_min_sizes: HashMap<usize, usize>,
    /// Exact widths of locally constructed fixed schema values and their
    /// aliases. External Cells and unknown returned pointers never enter this map.
    local_schema_value_widths: HashMap<usize, usize>,
    /// Boolean temporaries consumed only by their defining block terminator.
    /// These can lower directly to a branch without a stack round trip.
    branch_only_vars: BTreeSet<usize>,
    /// Fixed-byte parameter pointer slots backed by a separate ABI length word.
    fixed_byte_param_size_offsets: HashMap<usize, usize>,
    /// Fixed-width aggregate pointer slots backed by ABI bytes, keyed by IR variable id.
    aggregate_pointer_sources: HashMap<usize, AggregatePointerSource>,
    /// Tuple-valued call results that can be projected from RISC-V return registers.
    tuple_call_return_vars: HashMap<usize, IrType>,
    /// Stack slots populated from tuple call return registers, keyed by `(tuple_var_id, field)`.
    tuple_call_return_field_slots: HashMap<(usize, String), usize>,
    /// Tuple aggregate fields produced in the current function body, keyed by tuple var id.
    tuple_aggregate_fields: HashMap<usize, Vec<IrOperand>>,
    /// Fixed scalar temporaries that are aliases for schema-backed field loads.
    schema_field_value_sources: HashMap<usize, SchemaFieldValueSource>,
    /// U64 temporaries that can be recomputed in the CKB-runtime prelude.
    prelude_u64_value_sources: HashMap<usize, PreludeU64ValueSource>,
    /// Fixed scalar temporaries that can be recomputed as immediates in the CKB-runtime prelude.
    prelude_scalar_immediates: HashMap<usize, u64>,
    /// Fixed-byte constant temporaries that can be recomputed byte-by-byte in the CKB-runtime prelude.
    prelude_fixed_byte_constants: HashMap<usize, Vec<u8>>,
    /// Function-local 16-byte storage for materialized u128 values.
    u128_value_offsets: HashMap<usize, usize>,
    /// Function-local fixed-byte storage for wide scalar temporaries such as u128.
    fixed_byte_local_offsets: HashMap<usize, usize>,
    /// Named IR variable slots used by StoreVar/LoadVar instructions.
    named_var_offsets: HashMap<String, usize>,
    /// Deduplicated immutable byte constants emitted into .rodata.
    const_data_labels: HashMap<Vec<u8>, String>,
    const_data_entries: Vec<(String, Vec<u8>)>,
    /// Local pure functions proven to return one constant on every path.
    pure_const_returns: HashMap<String, IrConst>,
    /// Per-CKB-runtime cell data buffers keyed by IR variable id.
    cell_buffer_offsets: HashMap<usize, usize>,
    /// Per-CKB-runtime cell size words keyed by IR variable id.
    cell_buffer_size_offsets: HashMap<usize, usize>,
    /// Entry-owned source-bound read window shared by nested exact Cell-data,
    /// Script and witness scalar helpers. `s11` addresses the four-way cache;
    /// `s10..s5` hold the validated most-recent window.
    exact_read_cache_offset: Option<usize>,
    /// Authoritative Cell locations resolved before backend storage layout.
    cell_bindings: Vec<IrCellBinding>,
    cell_locations_by_local: HashMap<usize, (u64, usize)>,
    /// Byte-size slots for dynamic Molecule values projected from schema table fields.
    dynamic_value_size_offsets: HashMap<usize, usize>,
    /// Empty collection temporaries that can be verified as empty Molecule vectors.
    empty_molecule_vector_vars: BTreeSet<usize>,
    /// Stack-backed local collection variables whose length word and buffer are emitted in this frame.
    stack_collection_vars: BTreeSet<usize>,
    /// Locally constructed `Vec<u8>` bytes keyed by collection variable id.
    constructed_byte_vectors: HashMap<usize, Vec<IrOperand>>,
    /// Root `CollectionNew` variable for aliases of locally constructed vectors.
    constructed_byte_vector_roots: HashMap<usize, usize>,
    /// Collection variable ids whose full construction is covered by create-output vector verification.
    verified_collection_construction_vectors: BTreeSet<usize>,
    /// `type_hash()` temporaries that can be loaded from a created Output cell's TypeHash field.
    output_type_hash_sources: HashMap<usize, (u64, usize)>,
    /// Schema parameter TypeHash pointer slots, keyed by source parameter variable id.
    param_type_hash_pointer_offsets: HashMap<usize, usize>,
    /// Schema parameter TypeHash length slots, keyed by source parameter variable id.
    param_type_hash_size_offsets: HashMap<usize, usize>,
    /// `type_hash()` temporaries backed by trusted parameter TypeHash ABI bytes.
    param_type_hash_sources: HashMap<usize, usize>,
    /// Consumed IR operand variable ids in source lowering order.
    consume_order: Vec<usize>,
    /// Consumed Input index keyed by IR operand variable id.
    consume_indices: HashMap<usize, usize>,
    /// Consumed named schema type keyed by IR operand variable id.
    consume_type_names: HashMap<usize, String>,
    /// Consumed IR operand variable id keyed by source binding name.
    consume_binding_ids: HashMap<String, usize>,
    /// Read-ref CellDep index keyed by IR destination variable id.
    read_ref_indices: HashMap<usize, usize>,
    /// Read-only schema parameter variable ids keyed by source binding name.
    read_ref_param_ids: HashMap<String, usize>,
    /// CKB Input index for read-only schema parameters keyed by IR variable id.
    read_ref_param_input_indices: HashMap<usize, usize>,
    /// CKB CellDep index for read_ref schema parameters keyed by IR variable id.
    read_ref_param_dep_indices: HashMap<usize, usize>,
    /// Proposed transaction Output parameter variable ids keyed by source binding name.
    output_param_ids: HashMap<String, usize>,
    /// Whether the current entry function should bind read-only schema params from Inputs.
    bind_readonly_schema_params: bool,
    /// Whether the current function is a CKB lock predicate entry.
    current_lock_entry: bool,
    /// Mutable schema parameter variable ids keyed by source binding name.
    mutate_param_ids: HashMap<String, usize>,
    /// Output index for source-level operations that materialize transaction Outputs.
    operation_output_indices: HashMap<usize, usize>,
    /// Operation destination ids whose transaction Output relation is fully verifier-covered.
    verified_operation_outputs: BTreeSet<usize>,
    /// Collection push value ids whose effect is covered by a mutate append verifier.
    verified_collection_push_values: BTreeSet<usize>,
    /// Function-local cold fail handlers keyed by terminal verifier error code.
    fail_handler_codes: BTreeSet<CellScriptRuntimeError>,
    /// Whether generated fatal paths need the frame-free process EXIT routine.
    needs_process_failure_helper: bool,
    /// Unique label counter for runtime checks.
    next_runtime_label: usize,
    /// Final stack-frame size for typed action/lock/helper entries.
    entry_frame_sizes: BTreeMap<String, u32>,
}

impl CodeGenerator {
    fn fixed_named_type_width(&self, ty: &IrType) -> Option<usize> {
        match ty {
            IrType::Named(name) => self.type_fixed_sizes.get(name).copied().or_else(|| self.enum_fixed_sizes.get(name).copied()),
            IrType::Ref(inner) | IrType::MutRef(inner) => self.fixed_named_type_width(inner),
            _ => None,
        }
    }

    fn generic_value_type_width(&self, ty: &IrType) -> Option<usize> {
        let IrType::Named(name) = ty else {
            return None;
        };
        name.contains("__mono__").then(|| self.fixed_named_type_width(ty)).flatten()
    }

    fn fixed_byte_like_width(&self, ty: &IrType) -> Option<usize> {
        fixed_byte_width(ty, type_static_length(ty))
            .or_else(|| fixed_aggregate_pointer_param_width(ty))
            .or_else(|| self.fixed_named_type_width(ty))
    }

    fn payload_enum_width(&self, ty: &IrType) -> Option<usize> {
        let IrType::Named(name) = ty else {
            return None;
        };
        self.enum_layouts.get(name).filter(|layout| layout.has_payload()).map(|layout| layout.encoded_size)
    }

    fn fieldless_enum_width(&self, ty: &IrType) -> Option<usize> {
        let IrType::Named(name) = ty else {
            return None;
        };
        if !name.contains("__mono__") {
            return None;
        }
        self.enum_fixed_sizes.get(name).copied().filter(|_| !self.enum_layouts.get(name).is_some_and(IrEnumLayout::has_payload))
    }

    fn const_data_label_for_bytes(&mut self, bytes: Vec<u8>) -> String {
        if let Some(label) = self.const_data_labels.get(&bytes) {
            return label.clone();
        }
        let label = format!("__cellscript_const_data_{}", self.const_data_entries.len());
        self.const_data_labels.insert(bytes.clone(), label.clone());
        self.const_data_entries.push((label.clone(), bytes));
        label
    }

    fn emit_const_data_pool(&mut self) {
        if self.const_data_entries.is_empty() {
            return;
        }
        self.emit_section(".rodata");
        for (label, bytes) in self.const_data_entries.clone() {
            self.emit_label(&label);
            for byte in bytes {
                self.emit(format!(".byte {}", byte));
            }
            self.emit(".align 3");
        }
    }

    fn constructed_byte_vector_part_width(&self, operand: &IrOperand) -> Option<usize> {
        constructed_byte_vector_part_width(operand).or_else(|| match operand {
            IrOperand::Var(var) => self.fixed_named_type_width(&var.ty),
            _ => None,
        })
    }

    fn param_is_runtime_bound(&self, param: &IrParam) -> bool {
        abi::param_is_runtime_bound(param, &self.cell_type_names)
    }

    pub fn new(options: CodegenOptions) -> Self {
        Self {
            options,
            assembly: Vec::new(),
            current_function: None,
            current_function_owns_exact_read_cache: false,
            module_uses_exact_read_cache: false,
            module_uses_exact_read_hot_cache: false,
            frame_size: 16,
            next_virtual_output: 0,
            collection_region_start: 0,
            next_collection_slot: 0,
            type_layouts: HashMap::new(),
            enum_fixed_sizes: HashMap::new(),
            enum_layouts: HashMap::new(),
            type_fixed_sizes: HashMap::new(),
            receipt_type_names: BTreeSet::new(),
            cell_type_names: BTreeSet::new(),
            flow_states: HashMap::new(),
            flow_state_fields: HashMap::new(),
            flow_rules: HashMap::new(),
            current_state_transition_edges: Vec::new(),
            auto_aggregate_runtime_helpers_by_action: HashMap::new(),
            callable_abis: HashMap::new(),
            schema_pointer_vars: BTreeSet::new(),
            param_vars: BTreeSet::new(),
            schema_pointer_size_offsets: HashMap::new(),
            dominant_schema_exact_sizes: HashMap::new(),
            block_schema_exact_sizes: HashMap::new(),
            block_schema_min_sizes: HashMap::new(),
            local_schema_value_widths: HashMap::new(),
            branch_only_vars: BTreeSet::new(),
            fixed_byte_param_size_offsets: HashMap::new(),
            aggregate_pointer_sources: HashMap::new(),
            tuple_call_return_vars: HashMap::new(),
            tuple_call_return_field_slots: HashMap::new(),
            tuple_aggregate_fields: HashMap::new(),
            schema_field_value_sources: HashMap::new(),
            prelude_u64_value_sources: HashMap::new(),
            prelude_scalar_immediates: HashMap::new(),
            prelude_fixed_byte_constants: HashMap::new(),
            u128_value_offsets: HashMap::new(),
            fixed_byte_local_offsets: HashMap::new(),
            named_var_offsets: HashMap::new(),
            const_data_labels: HashMap::new(),
            const_data_entries: Vec::new(),
            pure_const_returns: HashMap::new(),
            cell_buffer_offsets: HashMap::new(),
            cell_buffer_size_offsets: HashMap::new(),
            exact_read_cache_offset: None,
            cell_bindings: Vec::new(),
            cell_locations_by_local: HashMap::new(),
            dynamic_value_size_offsets: HashMap::new(),
            empty_molecule_vector_vars: BTreeSet::new(),
            stack_collection_vars: BTreeSet::new(),
            constructed_byte_vectors: HashMap::new(),
            constructed_byte_vector_roots: HashMap::new(),
            verified_collection_construction_vectors: BTreeSet::new(),
            output_type_hash_sources: HashMap::new(),
            param_type_hash_pointer_offsets: HashMap::new(),
            param_type_hash_size_offsets: HashMap::new(),
            param_type_hash_sources: HashMap::new(),
            consume_order: Vec::new(),
            consume_indices: HashMap::new(),
            consume_type_names: HashMap::new(),
            consume_binding_ids: HashMap::new(),
            read_ref_indices: HashMap::new(),
            read_ref_param_ids: HashMap::new(),
            read_ref_param_input_indices: HashMap::new(),
            read_ref_param_dep_indices: HashMap::new(),
            output_param_ids: HashMap::new(),
            bind_readonly_schema_params: false,
            current_lock_entry: false,
            mutate_param_ids: HashMap::new(),
            operation_output_indices: HashMap::new(),
            verified_operation_outputs: BTreeSet::new(),
            verified_collection_push_values: BTreeSet::new(),
            fail_handler_codes: BTreeSet::new(),
            needs_process_failure_helper: false,
            next_runtime_label: 0,
            entry_frame_sizes: BTreeMap::new(),
        }
    }

    fn runtime_abi(&self) -> RuntimeSyscallAbi {
        runtime_syscall_abi(self.options.target_profile)
    }

    pub(super) fn resolved_cell_location(&self, role: IrCellBindingRole, binding: &str) -> Option<(u64, usize)> {
        self.cell_bindings
            .iter()
            .find(|entry| entry.role == role && entry.binding == binding)
            .map(|entry| (cell_source_value(entry.source), entry.ordinal))
    }

    pub(super) fn resolved_cell_location_for_local(&self, local: usize) -> Option<(u64, usize)> {
        self.cell_locations_by_local.get(&local).copied()
    }

    pub(super) fn require_cell_location(&mut self, role: IrCellBindingRole, binding: &str) -> (u64, usize) {
        if let Some(location) = self.resolved_cell_location(role, binding) {
            return location;
        }
        self.emit(format!("# cellscript abi: unresolved {:?} Cell binding {}", role, binding));
        self.emit_fail(CellScriptRuntimeError::CellLoadFailed);
        // Unreachable after the emitted failure; never substitute a live Cell.
        (CKB_SOURCE_INPUT, usize::MAX)
    }

    fn require_output_slot(&mut self, binding: &str, ordinal: usize) -> (u64, usize) {
        if let Some(record) = self
            .cell_bindings
            .iter()
            .find(|record| record.role == IrCellBindingRole::Output && record.binding == binding && record.ordinal == ordinal)
        {
            return (cell_source_value(record.source), record.ordinal);
        }
        self.emit(format!("# cellscript abi: unresolved output Cell binding {} at {}", binding, ordinal));
        self.emit_fail(CellScriptRuntimeError::CellLoadFailed);
        (CKB_SOURCE_OUTPUT, usize::MAX)
    }

    pub fn generate(self, ir: &IrModule, format: ArtifactFormat) -> Result<Vec<u8>> {
        self.generate_with_evidence(ir, format).map(|generated| generated.bytes)
    }

    pub fn generate_with_evidence(mut self, ir: &IrModule, format: ArtifactFormat) -> Result<GeneratedArtifact> {
        ir.validate_entry_selection()?;
        let has_entrypoint = ir.items.iter().any(|item| matches!(item, IrItem::Action(_) | IrItem::Lock(_)));
        self.enum_fixed_sizes = ir.enum_fixed_sizes.clone();
        self.enum_layouts = ir.enum_layouts.clone();
        self.pure_const_returns = collect_pure_const_returns(ir);
        let exact_read_sites = ir
            .items
            .iter()
            .filter_map(|item| match item {
                IrItem::Action(entry) => Some(&entry.body),
                IrItem::Lock(entry) => Some(&entry.body),
                IrItem::PureFn(entry) => Some(&entry.body),
                _ => None,
            })
            .flat_map(|body| &body.blocks)
            .flat_map(|block| &block.instructions)
            .filter(|instruction| matches!(instruction, IrInstruction::Call { func, .. } if is_cached_exact_read_helper(func)))
            .count();
        self.module_uses_exact_read_cache = exact_read_sites > 0;
        self.module_uses_exact_read_hot_cache =
            self.options.opt_level > 0 && exact_read_sites >= RUNTIME_EXACT_READ_HOT_SITE_THRESHOLD;
        self.auto_aggregate_runtime_helpers_by_action = auto_lowered_aggregate_runtime_helpers_by_action(ir);
        for item in &ir.items {
            if let IrItem::TypeDef(type_def) = item {
                self.register_type_def(type_def);
            }
        }
        for type_def in &ir.external_type_defs {
            self.register_type_def(type_def);
        }
        self.register_callable_abis(ir);

        self.emit_header();

        for item in &ir.items {
            if let IrItem::TypeDef(type_def) = item {
                self.generate_type_def(type_def).map_err(|error| with_codegen_code(error, "E2100"))?;
            }
        }

        self.emit_section(".text");
        if let IrEntrySelection::Artifact(declaration) = &ir.entry_selection {
            self.emit_policy_entry_wrapper(declaration, ir).map_err(|error| with_codegen_code(error, "E2101"))?;
        } else if let Some(entry) = ir.resolved_entry() {
            let (entry_name, entry_params) = (entry.name(), entry.params());
            if entry_params.is_empty() {
                self.emit_entry_direct_wrapper(entry_name);
            } else {
                self.emit_entry_witness_wrapper(entry_name, entry_params).map_err(|error| with_codegen_code(error, "E2101"))?;
            }
        }

        for item in &ir.items {
            if let IrItem::Action(action) = item {
                self.generate_action(action).map_err(|error| with_codegen_code(error, "E2102"))?;
            }
        }
        for item in &ir.items {
            if let IrItem::Lock(lock) = item {
                self.generate_lock(lock).map_err(|error| with_codegen_code(error, "E2103"))?;
            }
        }
        if has_entrypoint {
            for item in &ir.items {
                if let IrItem::PureFn(function) = item {
                    self.generate_pure_fn(function).map_err(|error| with_codegen_code(error, "E2104"))?;
                }
            }
        }

        // Runtime helpers own their frames and must never reuse the final
        // source function's cold handlers or epilogue.
        self.current_function = None;
        self.generate_runtime_support(ir);
        self.emit_process_failure_helper();
        self.emit_const_data_pool();

        if self.options.opt_level > 0 {
            eliminate_immediate_stack_reloads(&mut self.assembly);
        }

        let generated = match format {
            ArtifactFormat::RiscvAssembly => GeneratedArtifact { bytes: self.assembly.join("\n").into_bytes(), machine_layout: None },
            ArtifactFormat::RiscvElf => {
                let machine_layout = machine_layout_evidence(&self.assembly, &self.entry_frame_sizes, ir)
                    .map_err(|error| with_codegen_code(error, "E2201"))?;
                let bytes = assemble_generated_elf(&self.assembly).map_err(|error| with_codegen_code(error, "E2300"))?;
                GeneratedArtifact { bytes, machine_layout: Some(machine_layout) }
            }
        };
        Ok(generated)
    }

    fn emit_header(&mut self) {
        self.assembly.push("# CellScript Generated Assembly".to_string());
        self.assembly.push(format!("# opt_level={}, debug={}", self.options.opt_level, self.options.debug));
        self.assembly.push(".option arch, +rv64imac_zbb".to_string());
        self.assembly.push("".to_string());
    }

    fn emit_section(&mut self, section: &str) {
        self.assembly.push(format!(".section {}", section));
    }

    fn emit_global(&mut self, name: &str) {
        self.assembly.push(format!(".global {}", name));
        self.assembly.push(format!(".type {}, @function", name));
    }

    fn emit_label(&mut self, name: &str) {
        self.assembly.push(format!("{}:", name));
    }

    fn block_label(&self, block_id: BlockId) -> String {
        format!(".L{}_block_{}", self.current_function.as_deref().unwrap_or("fn"), block_id.0)
    }

    fn emit_jump_to_block(&mut self, block_id: BlockId, fallthrough: Option<BlockId>) {
        if Some(block_id) != fallthrough {
            self.emit(format!("j {}", self.block_label(block_id)));
        }
    }

    fn emit(&mut self, instruction: impl Into<String>) {
        let instruction = instruction.into();
        if self.emit_large_immediate_access_if_needed(&instruction) {
            return;
        }
        self.assembly.push(format!("    {}", instruction));
    }

    fn emit_large_immediate_access_if_needed(&mut self, instruction: &str) -> bool {
        let Some(clean) = strip_comment(instruction) else {
            return false;
        };
        if clean.is_empty() || clean.starts_with('.') || clean.ends_with(':') {
            return false;
        }

        let mut parts = clean.splitn(2, char::is_whitespace);
        let opcode = parts.next().unwrap_or_default();
        let args = parts.next().unwrap_or("").trim();
        let args = if args.is_empty() { Vec::new() } else { args.split(',').map(str::trim).collect::<Vec<_>>() };

        match opcode {
            "ld" | "lbu" if args.len() == 2 => {
                let Some((offset, base)) = memory_operand_offset_and_base(args[1]) else {
                    return false;
                };
                if parse_register(args[0]).is_err() || parse_register(base).is_err() {
                    return false;
                }
                if small_signed_immediate(offset) {
                    return false;
                }
                let scratch = scratch_register_avoiding(&[args[0], base]);
                self.assembly.push(format!("    li {}, {}", scratch, offset));
                self.assembly.push(format!("    add {}, {}, {}", scratch, base, scratch));
                self.assembly.push(format!("    {} {}, 0({})", opcode, args[0], scratch));
                true
            }
            "sb" | "sh" | "sw" | "sd" if args.len() == 2 => {
                let Some((offset, base)) = memory_operand_offset_and_base(args[1]) else {
                    return false;
                };
                if parse_register(args[0]).is_err() || parse_register(base).is_err() {
                    return false;
                }
                if small_signed_immediate(offset) {
                    return false;
                }
                let scratch = scratch_register_avoiding(&[args[0], base]);
                self.assembly.push(format!("    li {}, {}", scratch, offset));
                self.assembly.push(format!("    add {}, {}, {}", scratch, base, scratch));
                self.assembly.push(format!("    {} {}, 0({})", opcode, args[0], scratch));
                true
            }
            "addi" if args.len() == 3 => {
                let Ok(offset) = parse_immediate(args[2]) else {
                    return false;
                };
                if parse_register(args[0]).is_err() || parse_register(args[1]).is_err() {
                    return false;
                }
                if small_signed_immediate(offset) {
                    return false;
                }
                let scratch = scratch_register_avoiding(&[args[0], args[1]]);
                self.assembly.push(format!("    li {}, {}", scratch, offset));
                self.assembly.push(format!("    add {}, {}, {}", args[0], args[1], scratch));
                true
            }
            _ => false,
        }
    }

    fn generate_type_def(&mut self, type_def: &IrTypeDef) -> Result<()> {
        self.emit_section(".rodata");
        self.emit_label(&format!("__type_desc_{}", type_def.name));

        self.emit(format!(".word {}", type_def.fields.len()));

        for field in &type_def.fields {
            self.emit(format!(".byte {}", field.name.len()));
            self.emit(format!(".ascii \"{}\"", field.name));
            self.emit(".align 3");
            self.emit(format!(".word {}", self.type_id(&field.ty)));
        }

        Ok(())
    }

    fn register_type_def(&mut self, type_def: &IrTypeDef) {
        if let Some(fixed_size) = type_def.fields.iter().try_fold(0usize, |acc, field| field.fixed_size.map(|size| acc + size)) {
            self.type_fixed_sizes.insert(type_def.name.clone(), fixed_size);
        }
        if let Some(states) = &type_def.flow_states {
            self.flow_states.insert(type_def.name.clone(), states.clone());
        }
        if let Some(field) = &type_def.flow_state_field {
            self.flow_state_fields.insert(type_def.name.clone(), field.clone());
        }
        if !type_def.flow_rules.is_empty() {
            self.flow_rules.insert(type_def.name.clone(), type_def.flow_rules.clone());
        }
        if matches!(type_def.kind, IrTypeKind::Resource | IrTypeKind::Shared | IrTypeKind::Receipt) {
            self.cell_type_names.insert(type_def.name.clone());
            if type_def.kind == IrTypeKind::Receipt {
                self.receipt_type_names.insert(type_def.name.clone());
            }
        }
        let fields = type_def
            .fields
            .iter()
            .enumerate()
            .map(|(index, field)| {
                let fixed_enum_size = match &field.ty {
                    IrType::Named(name) => self.enum_fixed_sizes.get(name).copied(),
                    _ => None,
                };
                (
                    field.name.clone(),
                    SchemaFieldLayout {
                        index,
                        offset: field.offset,
                        ty: field.ty.clone(),
                        fixed_size: field.fixed_size,
                        fixed_enum_size,
                    },
                )
            })
            .collect();
        self.type_layouts.insert(type_def.name.clone(), fields);
    }

    fn register_callable_abis(&mut self, ir: &IrModule) {
        self.callable_abis.clear();
        for item in &ir.items {
            let (name, params, body) = match item {
                IrItem::Action(action) => (&action.name, &action.params, &action.body),
                IrItem::PureFn(function) => (&function.name, &function.params, &function.body),
                IrItem::Lock(lock) => (&lock.name, &lock.params, &lock.body),
                IrItem::TypeDef(_) | IrItem::Invariant(_) => continue,
            };
            let param_indices = params.iter().enumerate().map(|(index, param)| (param.binding.id, index)).collect::<HashMap<_, _>>();
            let mut type_hash_param_indices = BTreeSet::new();
            let (runtime_bound_param_indices, bounded_plan_param_indices) =
                abi::entry_abi_parameter_indices(params, body, &self.cell_type_names);
            for block in &body.blocks {
                for instruction in &block.instructions {
                    if let IrInstruction::TypeHash { operand: IrOperand::Var(var), .. } = instruction
                        && let Some(index) = param_indices.get(&var.id).copied()
                    {
                        type_hash_param_indices.insert(index);
                    }
                }
            }
            self.callable_abis.insert(
                name.clone(),
                CallableAbi {
                    params: params.clone(),
                    type_hash_param_indices,
                    runtime_bound_param_indices,
                    bounded_plan_param_indices,
                },
            );
        }
        for external in &ir.external_callable_abis {
            if self.callable_abis.contains_key(&external.name) {
                continue;
            }
            let runtime_bound_param_indices = external
                .params
                .iter()
                .enumerate()
                .filter_map(|(index, param)| self.param_is_runtime_bound(param).then_some(index))
                .collect();
            self.callable_abis.insert(
                external.name.clone(),
                CallableAbi {
                    params: external.params.clone(),
                    type_hash_param_indices: external.type_hash_param_indices.clone(),
                    runtime_bound_param_indices,
                    bounded_plan_param_indices: BTreeSet::new(),
                },
            );
        }
    }

    fn type_id(&self, ty: &IrType) -> u32 {
        match ty {
            IrType::U8 => 1,
            IrType::U16 => 2,
            IrType::U32 => 3,
            IrType::U64 => 4,
            IrType::U128 => 5,
            IrType::Bool => 6,
            IrType::Address => 7,
            IrType::Hash => 8,
            IrType::Array(_, _) => 9,
            IrType::Tuple(_) => 10,
            IrType::Named(_) => 11,
            IrType::Ref(_) => 12,
            IrType::MutRef(_) => 13,
            IrType::Unit => 14,
            IrType::I32 => 15,
        }
    }

    fn generate_action(&mut self, action: &IrAction) -> Result<()> {
        self.current_function = Some(action.name.clone());
        self.current_function_owns_exact_read_cache = true;
        self.current_state_transition_edges = action.state_transition_edges.clone();
        self.bind_readonly_schema_params = true;
        self.fail_handler_codes.clear();
        self.prepare_function_layout(&action.body, &action.params);
        self.entry_frame_sizes
            .entry(action.name.clone())
            .and_modify(|size| *size = (*size).max(self.frame_size as u32))
            .or_insert(self.frame_size as u32);
        self.next_virtual_output = 0;
        self.set_schema_pointer_params(&action.params);
        self.set_consumed_schema_pointers(&action.body);
        self.set_read_ref_schema_pointers(&action.body);
        self.set_pointer_aliases(&action.body);
        self.set_schema_field_value_sources(&action.body);
        self.set_verified_operation_outputs(&action.body);
        self.set_constructed_byte_vectors(&action.body);
        self.set_verified_collection_push_values(&action.body);

        if !action.params.is_empty() {
            self.emit_entry_abi_marker(&action.name);
        }
        self.emit_global(&action.name);
        self.emit_label(&action.name);

        self.emit_prologue();
        self.emit_param_spills(&action.params)?;
        self.emit_auto_aggregate_invariant_checks(&action.name);

        self.generate_body(&action.body)?;
        self.emit_shared_epilogue();

        self.current_function = None;
        self.current_function_owns_exact_read_cache = false;
        self.current_state_transition_edges.clear();
        self.bind_readonly_schema_params = false;
        self.schema_pointer_vars.clear();
        self.schema_pointer_size_offsets.clear();
        self.fixed_byte_param_size_offsets.clear();
        self.schema_field_value_sources.clear();
        self.aggregate_pointer_sources.clear();
        self.tuple_call_return_vars.clear();
        self.tuple_call_return_field_slots.clear();
        self.tuple_aggregate_fields.clear();
        self.output_type_hash_sources.clear();
        self.param_type_hash_pointer_offsets.clear();
        self.param_type_hash_size_offsets.clear();
        self.param_type_hash_sources.clear();
        self.prelude_u64_value_sources.clear();
        self.prelude_scalar_immediates.clear();
        self.prelude_fixed_byte_constants.clear();
        self.u128_value_offsets.clear();
        self.operation_output_indices.clear();
        self.verified_operation_outputs.clear();
        self.output_param_ids.clear();
        self.verified_collection_push_values.clear();
        self.stack_collection_vars.clear();
        self.constructed_byte_vectors.clear();
        self.constructed_byte_vector_roots.clear();
        self.verified_collection_construction_vectors.clear();
        self.param_vars.clear();
        Ok(())
    }

    fn emit_auto_aggregate_invariant_checks(&mut self, action_name: &str) {
        let helpers = self
            .auto_aggregate_runtime_helpers_by_action
            .get(action_name)
            .into_iter()
            .flat_map(|helpers| helpers.iter().cloned())
            .collect::<Vec<_>>();
        for helper in helpers {
            if helper == "__xudt_require_group_amount_conserved" {
                self.emit("# cellscript aggregate invariant: auto-lowered xUDT group amount conservation");
                self.emit("call __xudt_require_group_amount_conserved");
                let ok_label = self.fresh_label("auto_aggregate_xudt_conserved_ok");
                self.emit(format!("beqz a0, {}", ok_label));
                self.emit_process_failure_status();
                self.emit_label(&ok_label);
            }
        }
    }

    fn generate_pure_fn(&mut self, function: &IrPureFn) -> Result<()> {
        self.current_function = Some(function.name.clone());
        self.current_function_owns_exact_read_cache = false;
        self.bind_readonly_schema_params = false;
        self.fail_handler_codes.clear();
        self.prepare_function_layout(&function.body, &function.params);
        self.entry_frame_sizes.insert(function.name.clone(), self.frame_size as u32);
        self.next_virtual_output = 0;
        self.set_schema_pointer_params(&function.params);
        self.set_consumed_schema_pointers(&function.body);
        self.set_read_ref_schema_pointers(&function.body);
        self.set_pointer_aliases(&function.body);
        self.set_schema_field_value_sources(&function.body);
        self.set_verified_operation_outputs(&function.body);
        self.set_constructed_byte_vectors(&function.body);
        self.set_verified_collection_push_values(&function.body);

        self.emit_global(&function.name);
        self.emit_label(&function.name);

        self.emit_prologue();
        self.emit_param_spills(&function.params)?;
        self.generate_body(&function.body)?;
        self.emit_shared_epilogue();

        self.current_function = None;
        self.schema_pointer_vars.clear();
        self.schema_pointer_size_offsets.clear();
        self.fixed_byte_param_size_offsets.clear();
        self.schema_field_value_sources.clear();
        self.aggregate_pointer_sources.clear();
        self.tuple_call_return_vars.clear();
        self.tuple_call_return_field_slots.clear();
        self.tuple_aggregate_fields.clear();
        self.output_type_hash_sources.clear();
        self.param_type_hash_pointer_offsets.clear();
        self.param_type_hash_size_offsets.clear();
        self.param_type_hash_sources.clear();
        self.prelude_u64_value_sources.clear();
        self.prelude_scalar_immediates.clear();
        self.prelude_fixed_byte_constants.clear();
        self.u128_value_offsets.clear();
        self.operation_output_indices.clear();
        self.verified_operation_outputs.clear();
        self.output_param_ids.clear();
        self.verified_collection_push_values.clear();
        self.stack_collection_vars.clear();
        self.constructed_byte_vectors.clear();
        self.constructed_byte_vector_roots.clear();
        self.verified_collection_construction_vectors.clear();
        self.param_vars.clear();
        Ok(())
    }

    fn generate_lock(&mut self, lock: &IrLock) -> Result<()> {
        self.current_function = Some(lock.name.clone());
        self.current_function_owns_exact_read_cache = true;
        self.bind_readonly_schema_params = true;
        self.current_lock_entry = true;
        self.fail_handler_codes.clear();
        self.prepare_function_layout(&lock.body, &lock.params);
        self.entry_frame_sizes
            .entry(lock.name.clone())
            .and_modify(|size| *size = (*size).max(self.frame_size as u32))
            .or_insert(self.frame_size as u32);
        self.next_virtual_output = 0;
        self.set_schema_pointer_params(&lock.params);
        self.set_consumed_schema_pointers(&lock.body);
        self.set_read_ref_schema_pointers(&lock.body);
        self.set_pointer_aliases(&lock.body);
        self.set_schema_field_value_sources(&lock.body);
        self.set_verified_operation_outputs(&lock.body);
        self.set_constructed_byte_vectors(&lock.body);
        self.set_verified_collection_push_values(&lock.body);

        if !lock.params.is_empty() {
            self.emit_entry_abi_marker(&lock.name);
        }
        self.emit_global(&lock.name);
        self.emit_label(&lock.name);

        self.emit_prologue();
        self.emit_param_spills(&lock.params)?;

        self.generate_body(&lock.body)?;
        self.emit_shared_epilogue();

        self.current_function = None;
        self.current_function_owns_exact_read_cache = false;
        self.bind_readonly_schema_params = false;
        self.current_lock_entry = false;
        self.schema_pointer_vars.clear();
        self.schema_pointer_size_offsets.clear();
        self.fixed_byte_param_size_offsets.clear();
        self.schema_field_value_sources.clear();
        self.aggregate_pointer_sources.clear();
        self.tuple_call_return_vars.clear();
        self.tuple_call_return_field_slots.clear();
        self.tuple_aggregate_fields.clear();
        self.output_type_hash_sources.clear();
        self.param_type_hash_pointer_offsets.clear();
        self.param_type_hash_size_offsets.clear();
        self.param_type_hash_sources.clear();
        self.prelude_u64_value_sources.clear();
        self.prelude_scalar_immediates.clear();
        self.prelude_fixed_byte_constants.clear();
        self.u128_value_offsets.clear();
        self.operation_output_indices.clear();
        self.verified_operation_outputs.clear();
        self.output_param_ids.clear();
        self.verified_collection_push_values.clear();
        self.stack_collection_vars.clear();
        self.constructed_byte_vectors.clear();
        self.constructed_byte_vector_roots.clear();
        self.verified_collection_construction_vectors.clear();
        self.param_vars.clear();
        Ok(())
    }

    fn set_schema_pointer_params(&mut self, params: &[IrParam]) {
        self.schema_pointer_vars.clear();
        self.param_vars.clear();
        self.aggregate_pointer_sources.clear();
        for param in params {
            self.param_vars.insert(param.binding.id);
            if is_ckb_temporal_scalar_ir_type(&param.ty) || self.fieldless_enum_width(&param.ty).is_some() {
                continue;
            } else if named_type_name(&param.ty).is_some_and(|name| self.cell_type_names.contains(name)) {
                self.schema_pointer_vars.insert(param.binding.id);
            } else if self.generic_value_type_width(&param.ty).is_some()
                || fixed_byte_pointer_param_width(&param.ty).is_some()
                || fixed_aggregate_pointer_param_width(&param.ty).is_some()
            {
                self.aggregate_pointer_sources.insert(param.binding.id, AggregatePointerSource { ty: param.ty.clone() });
            } else if named_type_name(&param.ty).is_some() {
                self.schema_pointer_vars.insert(param.binding.id);
            }
        }
    }

    fn set_read_ref_schema_pointers(&mut self, body: &IrBody) {
        for block in &body.blocks {
            for instruction in &block.instructions {
                if let IrInstruction::ReadRef { dest, .. } = instruction {
                    self.schema_pointer_vars.insert(dest.id);
                    if let Some(size_offset) = self.cell_buffer_size_offsets.get(&dest.id).copied() {
                        self.schema_pointer_size_offsets.insert(dest.id, size_offset);
                    }
                }
            }
        }
    }

    fn set_consumed_schema_pointers(&mut self, body: &IrBody) {
        for block in &body.blocks {
            for instruction in &block.instructions {
                if let IrInstruction::BoundedCellLoad { dest, .. } = instruction {
                    self.schema_pointer_vars.insert(dest.id);
                    if let Some(size_offset) = self.cell_buffer_size_offsets.get(&dest.id).copied() {
                        self.schema_pointer_size_offsets.insert(dest.id, size_offset);
                    }
                }
                if let IrInstruction::BoundedPlanLoad { dest, .. } = instruction {
                    self.schema_pointer_vars.insert(dest.id);
                }
                if let Some(var) = consumed_operand_var(instruction) {
                    self.schema_pointer_vars.insert(var.id);
                    if let Some(size_offset) = self.cell_buffer_size_offsets.get(&var.id).copied() {
                        self.schema_pointer_size_offsets.insert(var.id, size_offset);
                    }
                }
            }
        }
    }

    fn set_pointer_aliases(&mut self, body: &IrBody) {
        let mut changed = true;
        while changed {
            changed = false;
            for block in &body.blocks {
                for instruction in &block.instructions {
                    let alias = match instruction {
                        IrInstruction::Unary { dest, op: UnaryOp::Ref | UnaryOp::Deref, operand: IrOperand::Var(src) }
                        | IrInstruction::Move { dest, src: IrOperand::Var(src) } => Some((dest, src)),
                        _ => None,
                    };
                    let Some((dest, src)) = alias else {
                        continue;
                    };
                    if let Some(location) = self.cell_locations_by_local.get(&src.id).copied()
                        && self.cell_locations_by_local.insert(dest.id, location) != Some(location)
                    {
                        changed = true;
                    }
                    if self.schema_pointer_vars.contains(&src.id) && self.schema_pointer_vars.insert(dest.id) {
                        changed = true;
                    }
                    if let Some(size_offset) = self.schema_pointer_size_offsets.get(&src.id).copied()
                        && self.schema_pointer_size_offsets.insert(dest.id, size_offset) != Some(size_offset)
                    {
                        changed = true;
                    }
                    if let Some(width) = self.local_schema_value_widths.get(&src.id).copied()
                        && self.local_schema_value_widths.insert(dest.id, width) != Some(width)
                    {
                        changed = true;
                    }
                    if let Some(size_offset) = self.fixed_byte_param_size_offsets.get(&src.id).copied()
                        && self.fixed_byte_param_size_offsets.insert(dest.id, size_offset) != Some(size_offset)
                    {
                        changed = true;
                    }
                    if let Some(size_offset) = self.dynamic_value_size_offsets.get(&src.id).copied()
                        && self.dynamic_value_size_offsets.insert(dest.id, size_offset) != Some(size_offset)
                    {
                        changed = true;
                    }
                    if let Some(size_offset) = self.cell_buffer_size_offsets.get(&src.id).copied()
                        && self.cell_buffer_size_offsets.insert(dest.id, size_offset) != Some(size_offset)
                    {
                        changed = true;
                    }
                    if let Some(buffer_offset) = self.cell_buffer_offsets.get(&src.id).copied()
                        && self.cell_buffer_offsets.insert(dest.id, buffer_offset) != Some(buffer_offset)
                    {
                        changed = true;
                    }
                    if self.empty_molecule_vector_vars.contains(&src.id) && self.empty_molecule_vector_vars.insert(dest.id) {
                        changed = true;
                    }
                    if let Some(source) = self.aggregate_pointer_sources.get(&src.id).cloned()
                        && self.aggregate_pointer_sources.insert(dest.id, source).is_none()
                    {
                        changed = true;
                    }
                }
            }
        }
    }

    fn set_schema_field_value_sources(&mut self, body: &IrBody) {
        self.schema_field_value_sources.clear();
        self.prelude_u64_value_sources.clear();
        self.prelude_scalar_immediates.clear();
        self.prelude_fixed_byte_constants.clear();
        self.tuple_call_return_vars.clear();
        self.tuple_call_return_field_slots.clear();
        self.tuple_aggregate_fields.clear();
        // These caches describe values for the entire body, not a program
        // point. A reassigned local must be read from its current stack slot;
        // retaining its initializer would also poison derived expressions.
        let destination = |instruction: &IrInstruction| match instruction {
            IrInstruction::LoadConst { dest, .. }
            | IrInstruction::LoadVar { dest, .. }
            | IrInstruction::Binary { dest, .. }
            | IrInstruction::Unary { dest, .. }
            | IrInstruction::FieldAccess { dest, .. }
            | IrInstruction::Index { dest, .. }
            | IrInstruction::Length { dest, .. }
            | IrInstruction::TypeHash { dest, .. }
            | IrInstruction::CollectionNew { dest, .. }
            | IrInstruction::CollectionCapacity { dest, .. }
            | IrInstruction::CollectionContains { dest, .. }
            | IrInstruction::CollectionRemove { dest, .. }
            | IrInstruction::CollectionPop { dest, .. }
            | IrInstruction::BoundedCellLoad { dest, .. }
            | IrInstruction::BoundedPlanLoad { dest, .. }
            | IrInstruction::ReadRef { dest, .. }
            | IrInstruction::Create { dest, .. }
            | IrInstruction::CreateUnique { dest, .. }
            | IrInstruction::ReplaceUnique { dest, .. }
            | IrInstruction::Transfer { dest, .. }
            | IrInstruction::Claim { dest, .. }
            | IrInstruction::Settle { dest, .. }
            | IrInstruction::Move { dest, .. }
            | IrInstruction::Tuple { dest, .. }
            | IrInstruction::EnumConstruct { dest, .. }
            | IrInstruction::EnumTag { dest, .. }
            | IrInstruction::EnumPayload { dest, .. }
            | IrInstruction::Call { dest: Some(dest), .. } => Some(dest.id),
            _ => None,
        };
        let mut seen = self.param_vars.clone();
        let mut reassigned = BTreeSet::new();
        for instruction in body.blocks.iter().flat_map(|block| &block.instructions) {
            if let Some(id) = destination(instruction)
                && !seen.insert(id)
            {
                reassigned.insert(id);
            }
        }
        let mut named_stack_collections = HashMap::<String, usize>::new();
        for block in &body.blocks {
            for instruction in &block.instructions {
                if destination(instruction).is_some_and(|id| reassigned.contains(&id)) {
                    continue;
                }
                match instruction {
                    IrInstruction::StoreVar { name, src: IrOperand::Var(src) } => {
                        if self.stack_collection_vars.contains(&src.id) {
                            named_stack_collections.insert(name.clone(), src.id);
                        }
                    }
                    IrInstruction::LoadVar { dest, name } => {
                        if named_stack_collections.contains_key(name) {
                            self.stack_collection_vars.insert(dest.id);
                        }
                    }
                    IrInstruction::Tuple { dest, fields } => {
                        self.tuple_aggregate_fields.insert(dest.id, fields.clone());
                    }
                    IrInstruction::Call { dest: Some(dest), .. } if matches!(dest.ty, IrType::Tuple(_)) => {
                        self.tuple_call_return_vars.insert(dest.id, dest.ty.clone());
                    }
                    IrInstruction::Call { dest: Some(dest), func, .. } if self.pure_const_returns.contains_key(func) => {
                        let value = self.pure_const_returns.get(func).cloned().expect("guarded pure const return");
                        if let Some(value) = fixed_scalar_const_value(&value) {
                            self.prelude_scalar_immediates.insert(dest.id, value);
                            if dest.ty == IrType::U64 {
                                self.prelude_u64_value_sources.insert(dest.id, PreludeU64ValueSource::Const(value));
                            }
                        }
                        if let Some(bytes) = fixed_byte_const_bytes(&value) {
                            self.prelude_fixed_byte_constants.insert(dest.id, bytes);
                        }
                    }
                    IrInstruction::LoadConst { dest, value } => {
                        if let Some(value) = fixed_scalar_const_value(value) {
                            self.prelude_scalar_immediates.insert(dest.id, value);
                            if dest.ty == IrType::U64 {
                                self.prelude_u64_value_sources.insert(dest.id, PreludeU64ValueSource::Const(value));
                            }
                        }
                        if let Some(bytes) = fixed_byte_const_bytes(value) {
                            self.prelude_fixed_byte_constants.insert(dest.id, bytes);
                        }
                    }
                    IrInstruction::FieldAccess { dest, obj: IrOperand::Var(obj), field } => {
                        if self
                            .tuple_call_return_vars
                            .get(&obj.id)
                            .and_then(|ty| tuple_return_field_type(ty, field))
                            .is_some_and(|field_ty| field_ty == dest.ty)
                        {
                            self.tuple_call_return_field_slots.entry((obj.id, field.clone())).or_insert(dest.id);
                            continue;
                        }
                        let source = if self.schema_pointer_vars.contains(&obj.id) {
                            let Some(type_name) = named_type_name(&obj.ty) else {
                                continue;
                            };
                            let Some(layout) = self.type_layouts.get(type_name).and_then(|fields| fields.get(field)).cloned() else {
                                continue;
                            };
                            Some(SchemaFieldValueSource {
                                obj_var_id: obj.id,
                                type_name: type_name.to_string(),
                                field: field.clone(),
                                layout,
                            })
                        } else if let Some(parent) = self.schema_field_value_sources.get(&obj.id) {
                            aggregate_field_layout(&obj.ty, field).map(|nested| {
                                let mut layout = nested;
                                layout.offset += parent.layout.offset;
                                SchemaFieldValueSource {
                                    obj_var_id: parent.obj_var_id,
                                    type_name: parent.type_name.clone(),
                                    field: format!("{}.{}", parent.field, field),
                                    layout,
                                }
                            })
                        } else {
                            self.aggregate_pointer_sources.get(&obj.id).and_then(|source| {
                                aggregate_field_layout(&source.ty, field).map(|layout| SchemaFieldValueSource {
                                    obj_var_id: obj.id,
                                    type_name: aggregate_type_label(&source.ty),
                                    field: field.clone(),
                                    layout,
                                })
                            })
                        };
                        let Some(source) = source else {
                            continue;
                        };
                        let layout = source.layout.clone();
                        let scalar_width = layout_fixed_scalar_width(&layout);
                        let field_width = layout_fixed_byte_width(&layout).or_else(|| self.fixed_named_type_width(&layout.ty));
                        if field_width.is_some()
                            && (layout.ty == dest.ty
                                || (scalar_width.is_some() && is_fixed_scalar_ir_type(&dest.ty))
                                || field_width == self.fixed_byte_like_width(&dest.ty))
                        {
                            self.schema_field_value_sources.insert(dest.id, source.clone());
                            if scalar_width.is_some() {
                                self.prelude_u64_value_sources.insert(dest.id, PreludeU64ValueSource::Field(source));
                            }
                        }
                    }
                    IrInstruction::Index { dest, arr: IrOperand::Var(arr), idx } => {
                        if self.aggregate_pointer_sources.contains_key(&arr.id) {
                            if let (IrType::Array(inner, len), Some(index)) = (&arr.ty, const_usize_operand(idx)) {
                                let element_ty = inner.as_ref();
                                if index < *len && type_static_length(element_ty).is_some() {
                                    if fixed_scalar_width(element_ty, type_static_length(element_ty)).is_some()
                                        && element_ty == &dest.ty
                                    {
                                        if dest.ty == IrType::U64 {
                                            self.prelude_u64_value_sources.insert(dest.id, PreludeU64ValueSource::StackVar(dest.id));
                                        }
                                    } else {
                                        self.aggregate_pointer_sources
                                            .insert(dest.id, AggregatePointerSource { ty: element_ty.clone() });
                                    }
                                }
                            }
                        } else if self.stack_collection_vars.contains(&arr.id)
                            && molecule_vector_element_fixed_width(&arr.ty, &self.type_fixed_sizes, &self.enum_fixed_sizes)
                                .is_some_and(|element_width| {
                                    self.fixed_byte_like_width(&dest.ty)
                                        .is_some_and(|dest_width| dest_width == element_width && dest_width > 8)
                                })
                        {
                            self.aggregate_pointer_sources.insert(dest.id, AggregatePointerSource { ty: dest.ty.clone() });
                        }
                    }
                    IrInstruction::Binary { dest, op, left, right }
                        if dest.ty == IrType::U64 && matches!(op, BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul | BinaryOp::Div) =>
                    {
                        let Some(left) = self.prelude_u64_value_source(left) else {
                            continue;
                        };
                        let Some(right) = self.prelude_u64_operand_source(right) else {
                            continue;
                        };
                        self.prelude_u64_value_sources
                            .insert(dest.id, PreludeU64ValueSource::Binary { op: *op, left: Box::new(left), right });
                    }
                    IrInstruction::Call { dest: Some(dest), func, args }
                        if dest.ty == IrType::U64 && is_min_call(func) && args.len() == 2 =>
                    {
                        let Some(left) = self.prelude_u64_value_source(&args[0]) else {
                            continue;
                        };
                        let Some(right) = self.prelude_u64_operand_source(&args[1]) else {
                            continue;
                        };
                        self.prelude_u64_value_sources.insert(dest.id, PreludeU64ValueSource::Min { left: Box::new(left), right });
                    }
                    IrInstruction::Call { dest: Some(dest), func, .. }
                        if (dest.ty == IrType::U64 || is_ckb_temporal_scalar_ir_type(&dest.ty))
                            && is_runtime_header_u64_call(func) =>
                    {
                        self.prelude_u64_value_sources.insert(dest.id, PreludeU64ValueSource::StackVar(dest.id));
                    }
                    IrInstruction::Length { dest, operand }
                        if dest.ty == IrType::U64
                            && (self.static_length(operand).is_some()
                                || self.dynamic_length_from_size_offset(operand).is_some()
                                || matches!(
                                    operand,
                                    IrOperand::Var(var)
                                        if self.dynamic_value_size_offsets.contains_key(&var.id)
                                            || self.schema_pointer_size_offsets.contains_key(&var.id)
                                )) =>
                    {
                        self.prelude_u64_value_sources.insert(dest.id, PreludeU64ValueSource::StackVar(dest.id));
                    }
                    IrInstruction::CollectionCapacity { dest, collection: IrOperand::Var(collection) }
                        if dest.ty == IrType::U64
                            && self.stack_collection_vars.contains(&collection.id)
                            && molecule_vector_element_fixed_width(&collection.ty, &self.type_fixed_sizes, &self.enum_fixed_sizes)
                                .is_some_and(|width| width != 0) =>
                    {
                        self.prelude_u64_value_sources.insert(dest.id, PreludeU64ValueSource::StackVar(dest.id));
                    }
                    IrInstruction::CollectionRemove { dest, collection: IrOperand::Var(collection), .. }
                    | IrInstruction::CollectionPop { dest, collection: IrOperand::Var(collection) }
                        if self.stack_collection_vars.contains(&collection.id)
                            && molecule_vector_element_fixed_width(&collection.ty, &self.type_fixed_sizes, &self.enum_fixed_sizes)
                                .is_some_and(|element_width| {
                                    self.fixed_byte_like_width(&dest.ty)
                                        .is_some_and(|dest_width| dest_width == element_width && dest_width > 8)
                                }) =>
                    {
                        self.aggregate_pointer_sources.insert(dest.id, AggregatePointerSource { ty: dest.ty.clone() });
                    }
                    IrInstruction::Move { dest, src } if dest.ty == IrType::U64 => {
                        if self.prelude_u64_value_source(src).is_some() {
                            self.prelude_u64_value_sources.insert(dest.id, PreludeU64ValueSource::StackVar(dest.id));
                        }
                    }
                    IrInstruction::Move { dest, src }
                        if matches!(dest.ty, IrType::Bool | IrType::U8 | IrType::U16 | IrType::U32 | IrType::I32) =>
                    {
                        if let Some(value) = self.prelude_scalar_immediate(src) {
                            self.prelude_scalar_immediates.insert(dest.id, value);
                        }
                    }
                    IrInstruction::Move { dest, src } if fixed_byte_width(&dest.ty, type_static_length(&dest.ty)).is_some() => {
                        if let Some(bytes) = self.prelude_fixed_byte_constant(src) {
                            self.prelude_fixed_byte_constants.insert(dest.id, bytes);
                        }
                    }
                    IrInstruction::Move { dest, src: IrOperand::Var(src) }
                    | IrInstruction::Unary { dest, op: UnaryOp::Ref | UnaryOp::Deref, operand: IrOperand::Var(src) } => {
                        if self.stack_collection_vars.contains(&src.id) && dest.ty == src.ty {
                            self.stack_collection_vars.insert(dest.id);
                        }
                        if let Some(source) = self.schema_field_value_sources.get(&src.id).cloned() {
                            self.schema_field_value_sources.insert(dest.id, source);
                        }
                    }
                    IrInstruction::CollectionNew { dest, .. } => {
                        self.stack_collection_vars.insert(dest.id);
                    }
                    _ => {}
                }
            }
        }
        let max_provenance_iterations = body.blocks.iter().map(|block| block.instructions.len()).sum::<usize>() + 1;
        for _ in 0..max_provenance_iterations {
            let mut changed = false;
            for block in &body.blocks {
                for instruction in &block.instructions {
                    match instruction {
                        IrInstruction::Move { dest, src: IrOperand::Var(src) }
                        | IrInstruction::Unary { dest, op: UnaryOp::Ref | UnaryOp::Deref, operand: IrOperand::Var(src) } => {
                            if !self.schema_field_value_sources.contains_key(&dest.id)
                                && let Some(source) = self.schema_field_value_sources.get(&src.id).cloned()
                            {
                                self.schema_field_value_sources.insert(dest.id, source);
                                changed = true;
                            }
                        }
                        _ => {}
                    }
                    let IrInstruction::FieldAccess { dest, obj: IrOperand::Var(obj), field } = instruction else {
                        continue;
                    };
                    if self.schema_field_value_sources.contains_key(&dest.id) {
                        continue;
                    }
                    let Some(parent) = self.schema_field_value_sources.get(&obj.id).cloned() else {
                        continue;
                    };
                    let Some(nested) = aggregate_field_layout(&obj.ty, field) else {
                        continue;
                    };
                    let mut layout = nested;
                    layout.offset += parent.layout.offset;
                    let scalar_width = layout_fixed_scalar_width(&layout);
                    let field_width = layout_fixed_byte_width(&layout).or_else(|| self.fixed_named_type_width(&layout.ty));
                    if field_width.is_none()
                        || !(layout.ty == dest.ty
                            || (scalar_width.is_some() && is_fixed_scalar_ir_type(&dest.ty))
                            || field_width == self.fixed_byte_like_width(&dest.ty))
                    {
                        continue;
                    }
                    let source = SchemaFieldValueSource {
                        obj_var_id: parent.obj_var_id,
                        type_name: parent.type_name,
                        field: format!("{}.{}", parent.field, field),
                        layout,
                    };
                    self.schema_field_value_sources.insert(dest.id, source.clone());
                    if scalar_width.is_some() {
                        self.prelude_u64_value_sources.insert(dest.id, PreludeU64ValueSource::Field(source));
                    }
                    changed = true;
                }
            }
            if !changed {
                return;
            }
        }
    }

    fn set_verified_operation_outputs(&mut self, body: &IrBody) {
        self.operation_output_indices.clear();
        self.verified_operation_outputs.clear();

        for block in &body.blocks {
            for instruction in &block.instructions {
                match instruction {
                    IrInstruction::Create { dest, .. }
                    | IrInstruction::CreateUnique { dest, .. }
                    | IrInstruction::ReplaceUnique { dest, .. } => {
                        if let Some((source, output_index)) = self.resolved_cell_location_for_local(dest.id) {
                            self.cell_locations_by_local.insert(dest.id, (source, output_index));
                            self.operation_output_indices.insert(dest.id, output_index);
                        }
                    }
                    IrInstruction::Transfer { dest, .. } => {
                        if let Some(output_index) = Self::create_output_index_for_dest(body, "transfer", dest) {
                            self.record_verified_operation_output(body, output_index, dest, "transfer");
                        }
                    }
                    IrInstruction::Claim { dest, .. } => {
                        if let Some(output_index) = Self::create_output_index_for_dest(body, "claim", dest) {
                            self.record_verified_operation_output(body, output_index, dest, "claim");
                        }
                    }
                    IrInstruction::Settle { dest, .. } => {
                        if let Some(output_index) = Self::create_output_index_for_dest(body, "settle", dest) {
                            self.record_verified_operation_output(body, output_index, dest, "settle");
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    fn create_output_index_for_dest(body: &IrBody, operation: &str, dest: &IrVar) -> Option<usize> {
        let binding = body.cell_binding_for_local(dest.id)?;
        (binding.role == IrCellBindingRole::Output
            && body.create_set.get(binding.ordinal).is_some_and(|pattern| pattern.operation == operation))
        .then_some(binding.ordinal)
    }

    fn record_verified_operation_output(&mut self, body: &IrBody, output_index: usize, dest: &IrVar, operation: &str) {
        self.operation_output_indices.insert(dest.id, output_index);
        if body
            .create_set
            .get(output_index)
            .is_some_and(|pattern| self.operation_output_pattern_is_verified(pattern, operation, &dest.ty))
        {
            self.verified_operation_outputs.insert(dest.id);
        }
    }

    fn operation_output_pattern_is_verified(&self, pattern: &CreatePattern, operation: &str, dest_ty: &IrType) -> bool {
        pattern.operation == operation
            && named_type_name(dest_ty).is_some_and(|type_name| type_name == pattern.ty.as_str())
            && self.can_verify_create_output_fields(pattern)
            && self.can_verify_output_lock(pattern)
    }

    fn set_verified_collection_push_values(&mut self, body: &IrBody) {
        self.verified_collection_push_values.clear();
        for pattern in &body.mutate_set {
            for transition in &pattern.transitions {
                if transition.op != MutateTransitionOp::Append {
                    continue;
                }
                let IrOperand::Var(var) = &transition.operand else {
                    continue;
                };
                let Some(layout) = self.type_layouts.get(&pattern.ty).and_then(|fields| fields.get(&transition.field)) else {
                    continue;
                };
                let Some(element_width) =
                    molecule_vector_element_fixed_width(&layout.ty, &self.type_fixed_sizes, &self.enum_fixed_sizes)
                else {
                    continue;
                };
                if self.fixed_append_fields(&transition.operand, element_width).is_some() {
                    self.verified_collection_push_values.insert(var.id);
                }
            }
        }
    }

    fn set_constructed_byte_vectors(&mut self, body: &IrBody) {
        self.stack_collection_vars.clear();
        self.constructed_byte_vectors.clear();
        self.constructed_byte_vector_roots.clear();
        self.verified_collection_construction_vectors.clear();
        let mut named_vectors = HashMap::<String, usize>::new();
        let mut named_stack_collections = HashMap::<String, usize>::new();
        let mut loaded_vector_names = HashMap::<usize, String>::new();
        for block in &body.blocks {
            for instruction in &block.instructions {
                match instruction {
                    IrInstruction::StoreVar { name, src: IrOperand::Var(src) } => {
                        if self.stack_collection_vars.contains(&src.id) {
                            named_stack_collections.insert(name.clone(), src.id);
                        }
                        if self.constructed_byte_vectors.contains_key(&src.id) {
                            named_vectors.insert(name.clone(), src.id);
                        }
                    }
                    IrInstruction::LoadVar { dest, name } => {
                        if let Some(source_id) = named_stack_collections.get(name).copied() {
                            self.stack_collection_vars.insert(dest.id);
                            named_stack_collections.insert(name.clone(), dest.id);
                            if let Some(bytes) = self.constructed_byte_vectors.get(&source_id).cloned() {
                                self.constructed_byte_vectors.insert(dest.id, bytes);
                                if let Some(root_id) = self.constructed_byte_vector_roots.get(&source_id).copied() {
                                    self.constructed_byte_vector_roots.insert(dest.id, root_id);
                                }
                                loaded_vector_names.insert(dest.id, name.clone());
                            }
                            continue;
                        }
                        if let Some(source_id) = named_vectors.get(name).copied()
                            && let Some(bytes) = self.constructed_byte_vectors.get(&source_id).cloned()
                        {
                            self.constructed_byte_vectors.insert(dest.id, bytes);
                            if let Some(root_id) = self.constructed_byte_vector_roots.get(&source_id).copied() {
                                self.constructed_byte_vector_roots.insert(dest.id, root_id);
                            }
                            loaded_vector_names.insert(dest.id, name.clone());
                        }
                    }
                    IrInstruction::CollectionNew { dest, .. } => {
                        self.stack_collection_vars.insert(dest.id);
                        self.constructed_byte_vectors.insert(dest.id, Vec::new());
                        self.constructed_byte_vector_roots.insert(dest.id, dest.id);
                    }
                    IrInstruction::CollectionPush { collection: IrOperand::Var(collection), value } => {
                        let width = self.constructed_byte_vector_part_width(value);
                        let source_available = width.is_some_and(|width| self.expected_fixed_byte_source(value, width).is_some());
                        if let Some(bytes) = self.constructed_byte_vectors.get_mut(&collection.id) {
                            if source_available {
                                bytes.push(value.clone());
                                if let Some(name) = loaded_vector_names.get(&collection.id).cloned() {
                                    named_vectors.insert(name, collection.id);
                                }
                            } else {
                                self.constructed_byte_vectors.remove(&collection.id);
                            }
                        }
                    }
                    IrInstruction::CollectionExtend { collection: IrOperand::Var(collection), slice } => {
                        let Some(width) = operand_fixed_byte_width(slice) else {
                            self.constructed_byte_vectors.remove(&collection.id);
                            continue;
                        };
                        let source_available = self.expected_fixed_byte_source(slice, width).is_some();
                        if let Some(bytes) = self.constructed_byte_vectors.get_mut(&collection.id) {
                            if source_available {
                                bytes.push(slice.clone());
                                if let Some(name) = loaded_vector_names.get(&collection.id).cloned() {
                                    named_vectors.insert(name, collection.id);
                                }
                            } else {
                                self.constructed_byte_vectors.remove(&collection.id);
                            }
                        }
                    }
                    IrInstruction::CollectionClear { collection: IrOperand::Var(collection) } => {
                        if let Some(bytes) = self.constructed_byte_vectors.get_mut(&collection.id) {
                            bytes.clear();
                            if let Some(name) = loaded_vector_names.get(&collection.id).cloned() {
                                named_vectors.insert(name, collection.id);
                            }
                        }
                    }
                    IrInstruction::CollectionReverse { collection: IrOperand::Var(collection) } => {
                        self.constructed_byte_vectors.remove(&collection.id);
                    }
                    IrInstruction::CollectionTruncate { collection: IrOperand::Var(collection), .. } => {
                        self.constructed_byte_vectors.remove(&collection.id);
                    }
                    IrInstruction::CollectionSwap { collection: IrOperand::Var(collection), .. } => {
                        self.constructed_byte_vectors.remove(&collection.id);
                    }
                    IrInstruction::CollectionInsert { collection: IrOperand::Var(collection), .. } => {
                        self.constructed_byte_vectors.remove(&collection.id);
                    }
                    IrInstruction::CollectionSet { collection: IrOperand::Var(collection), .. } => {
                        self.constructed_byte_vectors.remove(&collection.id);
                    }
                    IrInstruction::CollectionPop { collection: IrOperand::Var(collection), .. } => {
                        self.constructed_byte_vectors.remove(&collection.id);
                    }
                    IrInstruction::Move { dest, src: IrOperand::Var(src) }
                    | IrInstruction::Unary { dest, op: UnaryOp::Ref | UnaryOp::Deref, operand: IrOperand::Var(src) } => {
                        if self.stack_collection_vars.contains(&src.id) {
                            self.stack_collection_vars.insert(dest.id);
                        }
                        if let Some(bytes) = self.constructed_byte_vectors.get(&src.id).cloned() {
                            self.constructed_byte_vectors.insert(dest.id, bytes);
                            if let Some(root_id) = self.constructed_byte_vector_roots.get(&src.id).copied() {
                                self.constructed_byte_vector_roots.insert(dest.id, root_id);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        let mut verified_roots = BTreeSet::new();
        for pattern in &body.create_set {
            let Some(layouts) = self.type_layouts.get(&pattern.ty) else {
                continue;
            };
            for (field, value) in &pattern.fields {
                let Some(layout) = layouts.get(field) else {
                    continue;
                };
                if molecule_vector_element_fixed_width(&layout.ty, &self.type_fixed_sizes, &self.enum_fixed_sizes).is_none() {
                    continue;
                }
                let IrOperand::Var(var) = value else {
                    continue;
                };
                if self.constructed_byte_vectors.contains_key(&var.id) {
                    verified_roots.insert(self.constructed_byte_vector_roots.get(&var.id).copied().unwrap_or(var.id));
                }
            }
        }
        for (var_id, root_id) in &self.constructed_byte_vector_roots {
            if verified_roots.contains(root_id) {
                self.verified_collection_construction_vectors.insert(*var_id);
            }
        }
    }

    fn prelude_scalar_immediate(&self, operand: &IrOperand) -> Option<u64> {
        match operand {
            IrOperand::Const(value) => fixed_scalar_const_value(value),
            IrOperand::Var(var) => self.prelude_scalar_immediates.get(&var.id).copied(),
        }
    }

    fn prelude_fixed_byte_constant(&self, operand: &IrOperand) -> Option<Vec<u8>> {
        match operand {
            IrOperand::Const(value) => fixed_byte_const_bytes(value),
            IrOperand::Var(var) => self.prelude_fixed_byte_constants.get(&var.id).cloned(),
        }
    }

    fn prelude_u64_value_source(&self, operand: &IrOperand) -> Option<PreludeU64ValueSource> {
        match operand {
            IrOperand::Const(IrConst::U64(n)) => Some(PreludeU64ValueSource::Const(*n)),
            IrOperand::Var(var) if var.ty == IrType::U64 && self.param_vars.contains(&var.id) => {
                Some(PreludeU64ValueSource::ParamVar(var.id))
            }
            IrOperand::Var(var) => self.prelude_u64_value_sources.get(&var.id).cloned(),
            _ => None,
        }
    }

    fn prelude_u64_operand_source(&self, operand: &IrOperand) -> Option<PreludeU64OperandSource> {
        match operand {
            IrOperand::Const(IrConst::U64(n)) => Some(PreludeU64OperandSource::Const(*n)),
            IrOperand::Var(var) if var.ty == IrType::U64 && self.param_vars.contains(&var.id) => {
                Some(PreludeU64OperandSource::ParamVar(var.id))
            }
            IrOperand::Var(var) => match self.prelude_u64_value_sources.get(&var.id)? {
                PreludeU64ValueSource::Const(n) => Some(PreludeU64OperandSource::Const(*n)),
                PreludeU64ValueSource::ParamVar(var_id) => Some(PreludeU64OperandSource::ParamVar(*var_id)),
                PreludeU64ValueSource::StackVar(var_id) => Some(PreludeU64OperandSource::StackVar(*var_id)),
                PreludeU64ValueSource::Field(source) => Some(PreludeU64OperandSource::Field(source.clone())),
                PreludeU64ValueSource::Binary { .. } | PreludeU64ValueSource::Min { .. } => {
                    Some(PreludeU64OperandSource::Expr(Box::new(self.prelude_u64_value_sources.get(&var.id)?.clone())))
                }
            },
            _ => None,
        }
    }

    fn generate_body(&mut self, body: &IrBody) -> Result<()> {
        self.emit_resolved_cell_membership_checks();
        self.emit_read_ref_parameter_bindings();

        for (index, pattern) in body.consume_set.iter().enumerate() {
            self.generate_consume(pattern, index)?;
        }

        for instruction in body.blocks.iter().flat_map(|block| &block.instructions) {
            if let IrInstruction::ReadRef { dest, .. } = instruction {
                self.generate_read_ref(dest)?;
            }
        }

        // Signature-bound outputs are loaded in the entry prelude so
        // verification constraints can read them. Explicit `create name = ...` field
        // checks must stay in body order because their expected expressions may
        // depend on earlier `let`/index computations.
        let explicit_output_create_bindings = body
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .filter_map(|instruction| match instruction {
                IrInstruction::Create { pattern, .. }
                | IrInstruction::CreateUnique { pattern, .. }
                | IrInstruction::ReplaceUnique { pattern, .. } => Some(pattern.binding.as_str()),
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        for (index, pattern) in body.create_set.iter().enumerate() {
            if !matches!(pattern.operation.as_str(), "create" | "create_unique" | "replace_unique") {
                let explicit_output_create = explicit_output_create_bindings.contains(pattern.binding.as_str());
                self.generate_create(pattern, index, !explicit_output_create, explicit_output_create)?;
            }
        }

        for pattern in &body.mutate_set {
            self.generate_mutate_replacement(pattern)?;
        }

        for (index, block) in body.blocks.iter().enumerate() {
            let fallthrough = body.blocks.get(index + 1).map(|next| next.id);
            self.generate_block(block, fallthrough)?;
        }

        Ok(())
    }

    fn emit_read_ref_parameter_bindings(&mut self) {
        if self.read_ref_param_ids.values().any(|var_id| {
            !self.read_ref_param_input_indices.contains_key(var_id) && !self.read_ref_param_dep_indices.contains_key(var_id)
        }) {
            self.emit("# cellscript abi: fail closed because a read-only parameter has no resolved Cell binding");
            self.emit_fail(CellScriptRuntimeError::ConsumeInvalidOperand);
            return;
        }
        let mut input_bindings = self
            .read_ref_param_ids
            .iter()
            .filter_map(|(binding, var_id)| {
                self.read_ref_param_input_indices.get(var_id).copied().map(|input_index| (input_index, binding.clone(), *var_id))
            })
            .collect::<Vec<_>>();
        input_bindings.sort_by_key(|(input_index, _, _)| *input_index);
        for (input_index, binding, var_id) in input_bindings {
            let Some((source, resolved_index)) = self.resolved_cell_location_for_local(var_id) else {
                self.emit_fail(CellScriptRuntimeError::ConsumeInvalidOperand);
                return;
            };
            if resolved_index != input_index || !matches!(source, CKB_SOURCE_INPUT | CKB_SOURCE_GROUP_INPUT) {
                self.emit_fail(CellScriptRuntimeError::ConsumeInvalidOperand);
                return;
            }
            let Some(size_offset) = self.cell_buffer_size_offsets.get(&var_id).copied() else {
                continue;
            };
            let Some(buffer_offset) = self.cell_buffer_offsets.get(&var_id).copied() else {
                continue;
            };
            self.emit(format!(
                "# cellscript abi: bind read-only param {} to {}#{} cell data",
                binding,
                ckb_source_name(source),
                input_index
            ));
            self.emit_load_cell_data_syscall_to_offsets(
                "read_ref_param_input",
                source,
                input_index,
                size_offset,
                buffer_offset,
                RUNTIME_CELL_BUFFER_SIZE,
            );
            self.emit_return_on_syscall_error(CellScriptRuntimeError::SyscallFailed);
            self.emit_sp_addi("t0", buffer_offset);
            self.emit_stack_store("t0", var_id * 8);
        }

        let mut dep_bindings = self
            .read_ref_param_ids
            .iter()
            .filter_map(|(binding, var_id)| {
                self.read_ref_param_dep_indices.get(var_id).copied().map(|dep_index| (dep_index, binding.clone(), *var_id))
            })
            .collect::<Vec<_>>();
        dep_bindings.sort_by_key(|(dep_index, _, _)| *dep_index);
        for (dep_index, binding, var_id) in dep_bindings {
            if self.resolved_cell_location_for_local(var_id) != Some((CKB_SOURCE_CELL_DEP, dep_index)) {
                self.emit_fail(CellScriptRuntimeError::ConsumeInvalidOperand);
                return;
            }
            let Some(size_offset) = self.cell_buffer_size_offsets.get(&var_id).copied() else {
                continue;
            };
            let Some(buffer_offset) = self.cell_buffer_offsets.get(&var_id).copied() else {
                continue;
            };
            self.emit(format!("# cellscript abi: bind read-only param {} to CellDep#{} cell data", binding, dep_index));
            self.emit_load_cell_data_syscall_to_offsets(
                "read_ref_param_dep",
                CKB_SOURCE_CELL_DEP,
                dep_index,
                size_offset,
                buffer_offset,
                RUNTIME_CELL_BUFFER_SIZE,
            );
            self.emit_return_on_syscall_error(CellScriptRuntimeError::SyscallFailed);
            self.emit_sp_addi("t0", buffer_offset);
            self.emit_stack_store("t0", var_id * 8);
        }
    }

    fn generate_consume(&mut self, pattern: &CellPattern, index: usize) -> Result<()> {
        self.emit(format!("# {} input {}", pattern.operation, pattern.binding));
        let (source, input_index) = self.require_cell_location(IrCellBindingRole::Input, &pattern.binding);
        if let Some(var_id) =
            self.consume_binding_ids.get(&pattern.binding).copied().or_else(|| self.consume_order.get(index).copied())
            && let (Some(size_offset), Some(buffer_offset)) =
                (self.cell_buffer_size_offsets.get(&var_id).copied(), self.cell_buffer_offsets.get(&var_id).copied())
        {
            self.emit_load_cell_data_syscall_to_offsets(
                &pattern.operation,
                source,
                input_index,
                size_offset,
                buffer_offset,
                RUNTIME_CELL_BUFFER_SIZE,
            );
            self.emit_return_on_syscall_error(CellScriptRuntimeError::SyscallFailed);
            if let Some(type_name) = self.consume_type_names.get(&var_id).cloned()
                && let Some(expected_size) = self.type_fixed_sizes.get(&type_name).copied()
            {
                self.emit_dominating_schema_exact_size_check(size_offset, expected_size, &type_name);
            }
            self.emit_sp_addi("t0", buffer_offset);
            self.emit_stack_store("t0", var_id * 8);
            if pattern.operation == "destroy" {
                self.emit_destroy_group_output_absence_scan(pattern, input_index);
            }
            return Ok(());
        }

        self.emit_load_cell_data_syscall(&pattern.operation, source, input_index);
        self.emit_return_on_syscall_error(CellScriptRuntimeError::SyscallFailed);
        if pattern.operation == "destroy" {
            self.emit_destroy_group_output_absence_scan(pattern, input_index);
        }
        Ok(())
    }

    fn generate_read_ref(&mut self, dest: &IrVar) -> Result<()> {
        self.emit(format!("# read_ref {}", dest.name));
        if let (Some(size_offset), Some(buffer_offset)) =
            (self.cell_buffer_size_offsets.get(&dest.id).copied(), self.cell_buffer_offsets.get(&dest.id).copied())
        {
            let Some((CKB_SOURCE_CELL_DEP, dep_index)) = self.resolved_cell_location_for_local(dest.id) else {
                self.emit("# cellscript abi: fail closed because read_ref has no resolved CellDep binding");
                self.emit_fail(CellScriptRuntimeError::ConsumeInvalidOperand);
                return Ok(());
            };
            self.emit_load_cell_data_syscall_to_offsets(
                "read_ref",
                CKB_SOURCE_CELL_DEP,
                dep_index,
                size_offset,
                buffer_offset,
                RUNTIME_CELL_BUFFER_SIZE,
            );
            self.emit_return_on_syscall_error(CellScriptRuntimeError::SyscallFailed);
            if let Some(type_name) = named_type_name(&dest.ty)
                && let Some(expected_size) = self.type_fixed_sizes.get(type_name).copied()
            {
                self.emit_dominating_schema_exact_size_check(size_offset, expected_size, type_name);
            }
            self.emit_sp_addi("t0", buffer_offset);
            self.emit_stack_store("t0", dest.id * 8);
            return Ok(());
        }

        self.emit("# cellscript abi: fail closed because read_ref has no allocated destination");
        self.emit_fail(CellScriptRuntimeError::ConsumeInvalidOperand);
        Ok(())
    }

    fn generate_create(
        &mut self,
        pattern: &CreatePattern,
        index: usize,
        defer_unverifiable_output_fields: bool,
        defer_all_output_fields: bool,
    ) -> Result<()> {
        // The verifier cannot create cells inside CKB-VM; it can only verify the
        // transaction output selected by the lowering metadata.
        self.emit(format!("# {} output {}", pattern.operation, pattern.ty));
        let (source, index) = self.require_output_slot(&pattern.binding, index);
        if pattern.operation == "output" {
            if let Some(var_id) = self.output_param_ids.get(&pattern.binding).copied() {
                let Some(size_offset) = self.cell_buffer_size_offsets.get(&var_id).copied() else {
                    self.emit_fail(CellScriptRuntimeError::AssertionFailed);
                    return Ok(());
                };
                let Some(buffer_offset) = self.cell_buffer_offsets.get(&var_id).copied() else {
                    self.emit_fail(CellScriptRuntimeError::AssertionFailed);
                    return Ok(());
                };
                self.emit_load_cell_data_syscall_to_offsets(
                    "output_param",
                    source,
                    index,
                    size_offset,
                    buffer_offset,
                    RUNTIME_CELL_BUFFER_SIZE,
                );
                self.emit_return_on_syscall_error(CellScriptRuntimeError::SyscallFailed);
                self.emit_sp_addi("t0", buffer_offset);
                self.emit_stack_store("t0", var_id * 8);
                self.operation_output_indices.insert(var_id, index);
                if defer_all_output_fields {
                    self.emit("# cellscript abi: output field verification deferred to ordered create constraint");
                } else if pattern.fields.is_empty() {
                    self.emit_state_transition_check(pattern, size_offset, buffer_offset);
                } else if self.can_verify_create_output_fields(pattern) {
                    self.emit_create_output_checks_at(pattern, size_offset, buffer_offset);
                } else if defer_unverifiable_output_fields && self.create_output_fields_cover_type(pattern) {
                    self.emit("# cellscript abi: output field verification deferred to explicit verification constraints");
                } else {
                    self.emit("# cellscript abi: output field verification incomplete for this named output");
                    self.emit("# cellscript abi: fail closed because the output state is not fully verified");
                    self.emit_fail(CellScriptRuntimeError::AssertionFailed);
                    return Ok(());
                }
                if let Some(lock) = &pattern.lock {
                    if defer_all_output_fields {
                        self.emit("# cellscript abi: output lock verification deferred to ordered create constraint");
                        self.next_virtual_output = self.next_virtual_output.max(index + 1);
                        return Ok(());
                    }
                    if !(self.can_verify_output_lock(pattern) && self.emit_output_lock_hash_check(source, index, lock)) {
                        self.emit("# cellscript abi: output lock verification incomplete for this named output");
                        self.emit("# cellscript abi: fail closed because the output lock is not fully verified");
                        self.emit_fail(CellScriptRuntimeError::EntryWitnessMagicMismatch);
                        return Ok(());
                    }
                }
                self.next_virtual_output = self.next_virtual_output.max(index + 1);
                return Ok(());
            }
            self.emit_fail(CellScriptRuntimeError::AssertionFailed);
            return Ok(());
        }
        self.emit_load_cell_data_syscall(&pattern.operation, source, index);
        self.emit_return_on_syscall_error(CellScriptRuntimeError::SyscallFailed);

        if pattern.lock.is_some() {
            self.emit("# set lock script");
        }

        if self.can_verify_create_output_fields(pattern) {
            self.emit_create_output_checks(pattern);
        } else {
            self.emit("# cellscript abi: output field verification incomplete for this create pattern");
            self.emit("# cellscript abi: fail closed because the output state is not fully verified");
            self.emit_fail(CellScriptRuntimeError::AssertionFailed);
            return Ok(());
        }

        if let Some(lock) = &pattern.lock {
            if self.can_verify_output_lock(pattern) && self.emit_output_lock_hash_check(source, index, lock) {
                return Ok(());
            }
            self.emit("# cellscript abi: output lock verification incomplete for this create pattern");
            self.emit("# cellscript abi: fail closed because the output lock is not fully verified");
            self.emit_fail(CellScriptRuntimeError::EntryWitnessMagicMismatch);
        }

        Ok(())
    }

    fn generate_mutate_replacement(&mut self, pattern: &MutatePattern) -> Result<()> {
        self.emit(format!(
            "# mutate output {} {} Input#{} -> Output#{}",
            pattern.binding, pattern.ty, pattern.input_index, pattern.output_index
        ));
        self.emit_mutate_parameter_binding(pattern);
        if pattern.preserve_type_hash {
            self.emit_mutate_replacement_field_hash_check(
                pattern,
                CKB_CELL_FIELD_TYPE_HASH,
                "type_hash",
                CellScriptRuntimeError::TypeHashPreservationMismatch,
            );
        }
        if pattern.preserve_lock_hash {
            self.emit_mutate_replacement_field_hash_check(
                pattern,
                CKB_CELL_FIELD_LOCK_HASH,
                "lock_hash",
                CellScriptRuntimeError::LockHashPreservationMismatch,
            );
        }
        self.emit_mutate_replacement_preserved_field_checks(pattern);
        self.emit_mutate_replacement_transition_checks(pattern);
        self.emit_mutate_replacement_set_transition_checks(pattern);
        self.emit_mutate_replacement_u128_transition_checks(pattern);
        Ok(())
    }

    fn emit_mutate_parameter_binding(&mut self, pattern: &MutatePattern) {
        let Some(var_id) = self.mutate_param_ids.get(&pattern.binding).copied() else {
            return;
        };
        let Some(size_offset) = self.cell_buffer_size_offsets.get(&var_id).copied() else {
            return;
        };
        let Some(buffer_offset) = self.cell_buffer_offsets.get(&var_id).copied() else {
            return;
        };
        self.emit(format!("# cellscript abi: bind mutable param {} to Input#{} cell data", pattern.binding, pattern.input_index));
        let (source, index) = self.require_cell_location(IrCellBindingRole::Input, &pattern.binding);
        self.emit_load_cell_data_syscall_to_offsets(
            "mutate_param_input",
            source,
            index,
            size_offset,
            buffer_offset,
            RUNTIME_CELL_BUFFER_SIZE,
        );
        self.emit_return_on_syscall_error(CellScriptRuntimeError::SyscallFailed);
        self.emit_sp_addi("t0", buffer_offset);
        self.emit_stack_store("t0", var_id * 8);
    }

    fn generate_block(&mut self, block: &IrBlock, fallthrough: Option<BlockId>) -> Result<()> {
        self.block_schema_exact_sizes.clear();
        self.block_schema_min_sizes.clear();
        self.emit_label(&self.block_label(block.id));

        let fused = block.instructions.last().is_some_and(|instruction| self.can_fuse_branch(instruction, &block.terminator));
        let instruction_count = block.instructions.len().saturating_sub(usize::from(fused));
        for instruction in &block.instructions[..instruction_count] {
            self.generate_instruction(instruction)?;
        }
        if fused {
            self.try_emit_fused_branch(
                block.instructions.last().expect("fused branch has a defining instruction"),
                &block.terminator,
                fallthrough,
            )?;
        }

        if let Some(error) = block.runtime_error {
            self.emit_process_failure(error);
        } else if !fused {
            self.generate_terminator(&block.terminator, fallthrough)?;
        }

        Ok(())
    }

    fn can_fuse_branch(&self, instruction: &IrInstruction, terminator: &IrTerminator) -> bool {
        if self.options.opt_level == 0 {
            return false;
        }
        let IrInstruction::Binary { dest, op, left, right } = instruction else {
            return false;
        };
        let IrTerminator::Branch { cond: IrOperand::Var(cond), .. } = terminator else {
            return false;
        };
        dest.id == cond.id
            && self.branch_only_vars.contains(&dest.id)
            && matches!(dest.ty, IrType::Bool)
            && simple_scalar_operand(left)
            && simple_scalar_operand(right)
            && matches!(op, BinaryOp::Eq | BinaryOp::Ne | BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge)
    }

    fn try_emit_fused_branch(
        &mut self,
        instruction: &IrInstruction,
        terminator: &IrTerminator,
        fallthrough: Option<BlockId>,
    ) -> Result<bool> {
        let IrInstruction::Binary { dest, op, left, right } = instruction else {
            return Ok(false);
        };
        let IrTerminator::Branch { cond: IrOperand::Var(cond), then_block, else_block } = terminator else {
            return Ok(false);
        };
        if !self.can_fuse_branch(instruction, terminator) || dest.id != cond.id {
            return Ok(false);
        }

        self.emit_operand_to_register("t0", left);
        self.emit_operand_to_register("t1", right);
        let signed = binary_operands_signed_i32(left, right);
        let (true_branch, false_branch) = match op {
            BinaryOp::Eq => ("beq t0, t1", "bne t0, t1"),
            BinaryOp::Ne => ("bne t0, t1", "beq t0, t1"),
            BinaryOp::Lt if signed => ("blt t0, t1", "bge t0, t1"),
            BinaryOp::Lt => ("bltu t0, t1", "bgeu t0, t1"),
            BinaryOp::Le if signed => ("bge t1, t0", "blt t1, t0"),
            BinaryOp::Le => ("bgeu t1, t0", "bltu t1, t0"),
            BinaryOp::Gt if signed => ("blt t1, t0", "bge t1, t0"),
            BinaryOp::Gt => ("bltu t1, t0", "bgeu t1, t0"),
            BinaryOp::Ge if signed => ("bge t0, t1", "blt t0, t1"),
            BinaryOp::Ge => ("bgeu t0, t1", "bltu t0, t1"),
            _ => return Ok(false),
        };
        if Some(*then_block) == fallthrough {
            self.emit(format!("{false_branch}, {}", self.block_label(*else_block)));
        } else if Some(*else_block) == fallthrough {
            self.emit(format!("{true_branch}, {}", self.block_label(*then_block)));
        } else {
            self.emit(format!("{false_branch}, {}", self.block_label(*else_block)));
            self.emit_jump_to_block(*then_block, fallthrough);
        }
        Ok(true)
    }

    fn generate_instruction(&mut self, instruction: &IrInstruction) -> Result<()> {
        match instruction {
            IrInstruction::LoadConst { dest, value } => {
                self.emit_load_const(dest, value)?;
            }
            IrInstruction::LoadVar { dest, name } => {
                self.emit_load_var(dest, name)?;
            }
            IrInstruction::StoreVar { name, src } => {
                self.emit_store_var(name, src)?;
            }
            IrInstruction::Binary { dest, op, left, right } => {
                self.emit_binary(dest, *op, left, right)?;
            }
            IrInstruction::Unary { dest, op, operand } => {
                self.emit_unary(dest, *op, operand)?;
            }
            IrInstruction::FieldAccess { dest, obj, field } => {
                self.emit_field_access(dest, obj, field)?;
            }
            IrInstruction::Index { dest, arr, idx } => {
                self.emit_index(dest, arr, idx)?;
            }
            IrInstruction::Length { dest, operand } => {
                self.emit_length(dest, operand)?;
            }
            IrInstruction::TypeHash { dest, operand } => {
                self.emit_type_hash(dest, operand)?;
            }
            IrInstruction::CollectionNew { dest, ty, capacity } => {
                self.emit_collection_new(dest, ty, capacity.as_ref())?;
            }
            IrInstruction::CollectionCapacity { dest, collection } => {
                self.emit_collection_capacity(dest, collection)?;
            }
            IrInstruction::CollectionPush { collection, value } => {
                self.emit_collection_push(collection, value)?;
            }
            IrInstruction::CollectionExtend { collection, slice } => {
                self.emit_collection_extend(collection, slice)?;
            }
            IrInstruction::CollectionClear { collection } => {
                self.emit_collection_clear(collection)?;
            }
            IrInstruction::CollectionReverse { collection } => {
                self.emit_collection_reverse(collection)?;
            }
            IrInstruction::CollectionTruncate { collection, len } => {
                self.emit_collection_truncate(collection, len)?;
            }
            IrInstruction::CollectionSwap { collection, left, right } => {
                self.emit_collection_swap(collection, left, right)?;
            }
            IrInstruction::CollectionContains { dest, collection, value } => {
                self.emit_collection_contains(dest, collection, value)?;
            }
            IrInstruction::CollectionRemove { dest, collection, index } => {
                self.emit_collection_remove(dest, collection, index)?;
            }
            IrInstruction::CollectionInsert { collection, index, value } => {
                self.emit_collection_insert(collection, index, value)?;
            }
            IrInstruction::CollectionSet { collection, index, value } => {
                self.emit_collection_set(collection, index, value)?;
            }
            IrInstruction::CollectionPop { dest, collection } => {
                self.emit_collection_pop(dest, collection)?;
            }
            IrInstruction::BoundedCellLoad { dest, found, index, max_elements, element_type, element_width } => {
                self.emit_bounded_cell_load(dest, found, index, *max_elements, element_type, *element_width);
            }
            IrInstruction::BoundedPlanLoad { dest, found, plan, index, max_elements, element_type, element_width } => {
                self.emit_bounded_plan_load(dest, found, plan, index, *max_elements, element_type, *element_width);
            }
            IrInstruction::BoundedOutputVerify { index, pattern, capacity_floor_shannons } => {
                self.emit_bounded_output_verify(index, pattern, *capacity_floor_shannons);
            }
            IrInstruction::BoundedOutputEnd { index } => self.emit_bounded_output_end(index),
            IrInstruction::Call { dest, func, args } => {
                self.emit_call(dest.as_ref(), func, args)?;
            }
            IrInstruction::ReadRef { dest, ty } => {
                self.emit_read_ref(dest, ty)?;
            }
            IrInstruction::Move { dest, src } => {
                self.emit_move(dest, src)?;
            }
            IrInstruction::Tuple { dest, fields } => {
                self.emit_tuple(dest, fields)?;
            }
            IrInstruction::EnumConstruct { dest, enum_name, variant, fields } => {
                self.emit_enum_construct(dest, enum_name, variant, fields)?;
            }
            IrInstruction::EnumTag { dest, operand, enum_name } => {
                self.emit_enum_tag(dest, operand, enum_name)?;
            }
            IrInstruction::EnumPayload { dest, operand, enum_name, variant, field_index } => {
                self.emit_enum_payload(dest, operand, enum_name, variant, *field_index)?;
            }
            IrInstruction::Consume { operand } => {
                self.emit_consume(operand)?;
            }
            IrInstruction::Create { dest, pattern } => {
                self.emit_create(dest, pattern)?;
            }
            IrInstruction::Transfer { dest, operand, to } => {
                self.emit_transfer(dest, operand, to)?;
            }
            IrInstruction::Destroy { operand, policy: _ } => {
                self.emit_destroy(operand)?;
            }
            IrInstruction::Claim { dest, receipt } => {
                self.emit_claim(dest, receipt)?;
            }
            IrInstruction::Settle { dest, operand } => {
                self.emit_settle(dest, operand)?;
            }
            IrInstruction::CellMetadataEquality { left, right, field } => {
                self.emit_cell_metadata_equality(left, right, *field)?;
            }
            IrInstruction::CreateUnique { dest, pattern, identity } => {
                self.emit_create_unique(dest, pattern, identity)?;
            }
            IrInstruction::ReplaceUnique { dest, operand, pattern, identity } => {
                self.emit_replace_unique(dest, operand, pattern, identity)?;
            }
        }
        Ok(())
    }

    fn generate_terminator(&mut self, terminator: &IrTerminator, fallthrough: Option<BlockId>) -> Result<()> {
        match terminator {
            IrTerminator::Return(None) => {
                self.emit("li a0, 0");
                self.emit_epilogue();
            }
            IrTerminator::Return(Some(operand)) => {
                if !self.current_lock_entry && self.operand_is_u128_like(operand) {
                    self.emit("# cellscript abi: return u128 via a0(low)/a1(high)");
                    if self.emit_u128_operand_limbs("a0", "a1", "t6", "t4", operand, "u128 return") {
                        self.emit_epilogue();
                    }
                    return Ok(());
                }
                if let IrOperand::Var(var) = operand
                    && let IrType::Named(name) = &var.ty
                    && let Some(layout) = self.enum_layouts.get(name).filter(|layout| layout.has_payload()).cloned()
                {
                    let Some(source) = self.expected_fixed_byte_source(operand, layout.encoded_size) else {
                        self.emit("# cellscript abi: payload enum return source is unavailable; fail closed");
                        self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
                        return Ok(());
                    };
                    self.emit_prepare_fixed_byte_source(&source, layout.encoded_size, "payload enum return");
                    if !self.emit_fixed_byte_source_pointer_or_const_to("t4", &source) {
                        self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
                        return Ok(());
                    }
                    self.emit_unaligned_scalar_load("t4", "a0", "t2", 0, layout.encoded_size.min(8));
                    if layout.encoded_size > 8 {
                        self.emit_unaligned_scalar_load("t4", "a1", "t2", 8, layout.encoded_size - 8);
                    } else {
                        self.emit("li a1, 0");
                    }
                    self.emit(format!(
                        "# cellscript abi: return payload enum {} size={} via a0/a1 register pair",
                        name, layout.encoded_size
                    ));
                    self.emit_epilogue();
                    return Ok(());
                }
                if let IrOperand::Var(v) = operand
                    && let Some(fields) = self.tuple_aggregate_fields.get(&v.id).cloned()
                {
                    self.emit(format!("# cellscript abi: return tuple aggregate var{} fields={}", v.id, fields.len()));
                    if fields.is_empty() {
                        self.emit("li a0, 0");
                    }
                    for (index, field) in fields.iter().take(8).enumerate() {
                        self.emit(format!("# cellscript abi: return tuple field .{} via a{}", index, index));
                        self.emit_operand_to_register(&format!("a{}", index), field);
                    }
                    self.emit_epilogue();
                    return Ok(());
                }
                self.emit_operand_to_register("a0", operand);
                if self.current_lock_entry {
                    let ok_label = self.fresh_label("lock_predicate_true");
                    self.emit(format!("bnez a0, {}", ok_label));
                    self.emit_process_failure(CellScriptRuntimeError::AssertionFailed);
                    self.emit_label(&ok_label);
                    self.emit("li a0, 0");
                    self.emit_epilogue();
                    return Ok(());
                }
                self.emit_epilogue();
            }
            IrTerminator::Jump(block_id) => {
                self.emit_jump_to_block(*block_id, fallthrough);
            }
            IrTerminator::Branch { cond, then_block, else_block } => match cond {
                IrOperand::Const(IrConst::Bool(b)) => {
                    self.emit_jump_to_block(if *b { *then_block } else { *else_block }, fallthrough);
                }
                IrOperand::Const(IrConst::U64(n)) => {
                    self.emit_jump_to_block(if *n != 0 { *then_block } else { *else_block }, fallthrough);
                }
                IrOperand::Var(_) if then_block == else_block => {
                    self.emit_jump_to_block(*then_block, fallthrough);
                }
                IrOperand::Var(v) => {
                    self.emit_stack_load("t0", v.id * 8);
                    if Some(*then_block) == fallthrough {
                        self.emit(format!("beqz t0, {}", self.block_label(*else_block)));
                    } else if Some(*else_block) == fallthrough {
                        self.emit(format!("bnez t0, {}", self.block_label(*then_block)));
                    } else {
                        self.emit(format!("beqz t0, {}", self.block_label(*else_block)));
                        self.emit_jump_to_block(*then_block, fallthrough);
                    }
                }
                _ => {
                    self.emit_jump_to_block(*else_block, fallthrough);
                }
            },
        }
        Ok(())
    }

    fn emit_read_ref(&mut self, dest: &IrVar, ty: &str) -> Result<()> {
        if self.cell_buffer_offsets.contains_key(&dest.id) {
            self.emit(format!("# read_ref {} (preloaded from CellDep)", ty));
            return Ok(());
        }

        // Runtime fallback: emit LOAD_CELL_DATA syscall to load the cell dep data
        // into the scratch buffer and store the pointer.
        let Some(dep_index) = self.read_ref_indices.get(&dest.id).copied() else {
            self.emit("# cellscript abi: fail closed because read_ref CellDep index was not allocated");
            self.emit_fail(CellScriptRuntimeError::ConsumeInvalidOperand);
            return Ok(());
        };
        let size_offset = self.runtime_scratch_size_offset();
        let buffer_offset = self.runtime_scratch_buffer_offset();

        self.emit(format!("# read_ref {}", ty));
        self.emit(format!("# cellscript abi: runtime read_ref CellDep index={}", dep_index));
        self.emit_load_cell_data_syscall_to_offsets(
            "read_ref",
            CKB_SOURCE_CELL_DEP,
            dep_index,
            size_offset,
            buffer_offset,
            RUNTIME_SCRATCH_BUFFER_SIZE,
        );
        self.emit_return_on_syscall_error(CellScriptRuntimeError::SyscallFailed);
        self.emit_sp_addi("t0", buffer_offset);
        self.emit_stack_store("t0", dest.id * 8);

        // Also store the size so that subsequent schema operations can use it
        self.schema_pointer_size_offsets.insert(dest.id, size_offset);
        self.cell_buffer_size_offsets.insert(dest.id, size_offset);
        self.cell_buffer_offsets.insert(dest.id, buffer_offset);

        Ok(())
    }

    fn emit_move(&mut self, dest: &IrVar, src: &IrOperand) -> Result<()> {
        if dest.ty == IrType::U128 {
            self.emit_materialize_u128_operand_to_var(dest, src);
            return Ok(());
        }
        if let Some(width) = self.fixed_byte_like_width(&dest.ty).filter(|width| *width > 8)
            && self.emit_materialize_fixed_byte_operand_to_var(dest, src, width)
        {
            return Ok(());
        }
        self.emit_operand_to_register("t0", src);
        self.emit_stack_store("t0", dest.id * 8);
        Ok(())
    }

    fn emit_materialize_fixed_byte_operand_to_var(&mut self, dest: &IrVar, src: &IrOperand, width: usize) -> bool {
        let Some(dest_offset) = self.fixed_byte_local_offsets.get(&dest.id).copied() else {
            return false;
        };
        let Some(source) = self.expected_fixed_byte_source(src, width) else {
            self.emit("# cellscript abi: fail closed because fixed-byte move source is unavailable");
            self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
            return true;
        };
        self.emit(format!("# cellscript abi: materialize fixed-byte move var{} size={}", dest.id, width));
        self.emit_prepare_fixed_byte_source(&source, width, "fixed-byte move");
        if !self.emit_fixed_byte_source_pointer_or_const_to("a0", &source) {
            self.emit("# cellscript abi: fail closed because fixed-byte move pointer is unavailable");
            self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
            return true;
        }
        self.emit_sp_addi("a1", dest_offset);
        self.emit(format!("li a2, {}", width));
        self.emit("call __cellscript_memcpy_fixed");
        self.emit_sp_addi("t0", dest_offset);
        self.emit_stack_store("t0", dest.id * 8);
        true
    }

    fn emit_tuple(&mut self, dest: &IrVar, fields: &[IrOperand]) -> Result<()> {
        self.emit(format!("# cellscript abi: construct tuple aggregate var{} fields={}", dest.id, fields.len()));
        if self.emit_fixed_aggregate_tuple(dest, fields) {
            return Ok(());
        }
        if self.emit_fixed_named_tuple(dest, fields) {
            return Ok(());
        }
        self.emit_stack_store("zero", dest.id * 8);
        Ok(())
    }

    fn emit_fixed_aggregate_tuple(&mut self, dest: &IrVar, fields: &[IrOperand]) -> bool {
        if !matches!(dest.ty, IrType::Tuple(_) | IrType::Array(_, _)) {
            return false;
        }
        let Some(width) = type_static_length(&dest.ty).filter(|width| *width > 8) else {
            return false;
        };
        let Some(dest_offset) = self.fixed_byte_local_offsets.get(&dest.id).copied() else {
            return false;
        };
        self.emit(format!("# cellscript abi: materialize fixed {} var{} size={}", aggregate_type_label(&dest.ty), dest.id, width));
        for (index, field) in fields.iter().enumerate() {
            let Some(layout) = aggregate_field_layout(&dest.ty, &index.to_string()) else {
                return false;
            };
            let Some(field_width) = self.fixed_byte_like_width(&layout.ty).or_else(|| fixed_aggregate_pointer_param_width(&layout.ty))
            else {
                return false;
            };
            let Some(source) = self.expected_fixed_byte_source(field, field_width) else {
                self.emit("# cellscript abi: fixed tuple/array field source is unavailable; fail closed");
                self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
                return true;
            };
            self.emit_prepare_fixed_byte_source(&source, field_width, "fixed tuple/array field");
            if !self.emit_fixed_byte_source_pointer_or_const_to("a0", &source) {
                self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
                return true;
            }
            self.emit_sp_addi("a1", dest_offset + layout.offset);
            self.emit(format!("li a2, {}", field_width));
            self.emit("call __cellscript_memcpy_fixed");
        }
        self.emit_sp_addi("t0", dest_offset);
        self.emit_stack_store("t0", dest.id * 8);
        true
    }

    fn emit_enum_construct(&mut self, dest: &IrVar, enum_name: &str, variant_name: &str, fields: &[IrOperand]) -> Result<()> {
        let Some(layout) = self.enum_layouts.get(enum_name).cloned() else {
            return Err(CompileError::new(
                format!("payload enum '{}' reached codegen without an IR layout", enum_name),
                crate::error::Span::default(),
            ));
        };
        let Some(variant) = layout.variants.iter().find(|variant| variant.name == variant_name).cloned() else {
            return Err(CompileError::new(
                format!("payload enum '{}::{}' reached codegen without a variant layout", enum_name, variant_name),
                crate::error::Span::default(),
            ));
        };
        if fields.len() != variant.fields.len() {
            return Err(CompileError::new(
                format!(
                    "payload enum '{}::{}' codegen arity mismatch: expected {}, found {}",
                    enum_name,
                    variant_name,
                    variant.fields.len(),
                    fields.len()
                ),
                crate::error::Span::default(),
            ));
        }
        let Some(dest_offset) = self.fixed_byte_local_offsets.get(&dest.id).copied() else {
            return Err(CompileError::new(
                format!("payload enum '{}' destination has no fixed-byte local storage", enum_name),
                crate::error::Span::default(),
            ));
        };

        self.emit(format!(
            "# cellscript abi: construct payload enum {}::{} var{} tagged-union-v1 size={}",
            enum_name, variant_name, dest.id, layout.encoded_size
        ));
        self.emit_sp_addi("a0", dest_offset);
        self.emit(format!("li a1, {}", layout.encoded_size));
        self.emit("call __cellscript_memzero_fixed");
        self.emit_sp_addi("t4", dest_offset);
        self.emit(format!("li t0, {}", variant.tag));
        self.emit_memory_store_with_avoid("sb", "t0", "t4", 0, &["t0", "t4"]);

        for (operand, field) in fields.iter().zip(&variant.fields) {
            if field.width == 0 {
                continue;
            }
            if field.linear || (field.width <= 8 && is_fixed_scalar_ir_type(&field.ty)) {
                self.emit(format!(
                    "# cellscript abi: payload enum field {}.{}[{}] offset={} size={}{}",
                    enum_name,
                    variant_name,
                    field.index,
                    field.offset,
                    field.width,
                    if field.linear { " local-linear-handle" } else { "" }
                ));
                self.emit_operand_to_register("t0", operand);
                for byte_index in 0..field.width {
                    self.emit_memory_store_with_avoid("sb", "t0", "t4", field.offset + byte_index, &["t0", "t4"]);
                    if byte_index + 1 < field.width {
                        self.emit("srli t0, t0, 8");
                    }
                }
                continue;
            }

            let Some(source) = self.expected_fixed_byte_source(operand, field.width) else {
                self.emit("# cellscript abi: payload enum field source is unavailable; fail closed");
                self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
                return Ok(());
            };
            self.emit_prepare_fixed_byte_source(&source, field.width, "payload enum field");
            if !self.emit_fixed_byte_source_pointer_or_const_to("a0", &source) {
                self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
                return Ok(());
            }
            self.emit_sp_addi("a1", dest_offset + field.offset);
            self.emit(format!("li a2, {}", field.width));
            self.emit("call __cellscript_memcpy_fixed");
            self.emit_sp_addi("t4", dest_offset);
        }
        self.emit_sp_addi("t0", dest_offset);
        self.emit_stack_store("t0", dest.id * 8);
        Ok(())
    }

    fn emit_enum_tag(&mut self, dest: &IrVar, operand: &IrOperand, enum_name: &str) -> Result<()> {
        let Some(layout) = self.enum_layouts.get(enum_name).cloned() else {
            return Err(CompileError::new(
                format!("payload enum '{}' tag read has no IR layout", enum_name),
                crate::error::Span::default(),
            ));
        };
        let Some(source) = self.expected_fixed_byte_source(operand, layout.encoded_size) else {
            self.emit("# cellscript abi: payload enum tag source is unavailable; fail closed");
            self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
            return Ok(());
        };
        self.emit_prepare_fixed_byte_source(&source, layout.encoded_size, "payload enum tag");
        if !self.emit_fixed_byte_source_pointer_or_const_to("t4", &source) {
            self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
            return Ok(());
        }
        self.emit_memory_load_with_avoid("lbu", "t0", "t4", 0, &["t0", "t4"]);
        self.emit_stack_store("t0", dest.id * 8);
        Ok(())
    }

    fn emit_enum_payload(
        &mut self,
        dest: &IrVar,
        operand: &IrOperand,
        enum_name: &str,
        variant_name: &str,
        field_index: usize,
    ) -> Result<()> {
        let Some(layout) = self.enum_layouts.get(enum_name).cloned() else {
            return Err(CompileError::new(
                format!("payload enum '{}' projection has no IR layout", enum_name),
                crate::error::Span::default(),
            ));
        };
        let Some(field) = layout
            .variants
            .iter()
            .find(|variant| variant.name == variant_name)
            .and_then(|variant| variant.fields.get(field_index))
            .cloned()
        else {
            return Err(CompileError::new(
                format!("payload enum '{}::{}' field {} has no IR layout", enum_name, variant_name, field_index),
                crate::error::Span::default(),
            ));
        };
        let Some(source) = self.expected_fixed_byte_source(operand, layout.encoded_size) else {
            self.emit("# cellscript abi: payload enum projection source is unavailable; fail closed");
            self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
            return Ok(());
        };
        self.emit_prepare_fixed_byte_source(&source, layout.encoded_size, "payload enum projection");
        if !self.emit_fixed_byte_source_pointer_or_const_to("t4", &source) {
            self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
            return Ok(());
        }
        if field.width == 0 {
            self.emit_stack_store("zero", dest.id * 8);
            return Ok(());
        }
        if field.linear || (field.width <= 8 && is_fixed_scalar_ir_type(&field.ty)) {
            self.emit_unaligned_scalar_load("t4", "t0", "t2", field.offset, field.width);
            if field.ty == IrType::I32 {
                self.emit_sign_extend_i32("t0");
            }
            self.emit_stack_store("t0", dest.id * 8);
            return Ok(());
        }

        let Some(dest_offset) = self.fixed_byte_local_offsets.get(&dest.id).copied() else {
            self.emit("# cellscript abi: payload enum projection destination has no fixed-byte storage; fail closed");
            self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
            return Ok(());
        };
        self.emit_large_addi("a0", "t4", field.offset as i64);
        self.emit_sp_addi("a1", dest_offset);
        self.emit(format!("li a2, {}", field.width));
        self.emit("call __cellscript_memcpy_fixed");
        self.emit_sp_addi("t0", dest_offset);
        self.emit_stack_store("t0", dest.id * 8);
        Ok(())
    }

    fn emit_fixed_named_tuple(&mut self, dest: &IrVar, fields: &[IrOperand]) -> bool {
        let IrType::Named(type_name) = &dest.ty else {
            return false;
        };
        let Some(width) = self.type_fixed_sizes.get(type_name).copied() else {
            return false;
        };
        let Some(dest_offset) = self.fixed_byte_local_offsets.get(&dest.id).copied() else {
            return false;
        };
        let Some(layouts) = self.type_layouts.get(type_name) else {
            return false;
        };
        let mut ordered = layouts.values().cloned().collect::<Vec<_>>();
        ordered.sort_by_key(|layout| layout.offset);
        if ordered.len() != fields.len() {
            return false;
        }

        self.emit(format!("# cellscript abi: materialize fixed aggregate {} var{} size={}", type_name, dest.id, width));
        for (field, layout) in fields.iter().zip(ordered.iter()) {
            let Some(field_width) = layout_fixed_byte_width(layout).or_else(|| self.fixed_named_type_width(&layout.ty)) else {
                return false;
            };
            let Some(source) = self.expected_fixed_byte_source(field, field_width) else {
                self.emit("# cellscript abi: fail closed because fixed aggregate field source is unavailable");
                self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
                return true;
            };
            self.emit_prepare_fixed_byte_source(&source, field_width, &format!("{} aggregate field", type_name));
            if !self.emit_fixed_byte_source_pointer_or_const_to("a0", &source) {
                self.emit("# cellscript abi: fail closed because fixed aggregate field pointer is unavailable");
                self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
                return true;
            }
            self.emit_sp_addi("a1", dest_offset + layout.offset);
            self.emit(format!("li a2, {}", field_width));
            self.emit("call __cellscript_memcpy_fixed");
        }
        self.emit_sp_addi("t0", dest_offset);
        self.emit_stack_store("t0", dest.id * 8);
        true
    }

    fn emit_operand_to_register(&mut self, register: &str, operand: &IrOperand) {
        match operand {
            IrOperand::Const(IrConst::U8(n)) => self.emit(format!("li {}, {}", register, n)),
            IrOperand::Const(IrConst::U16(n)) => self.emit(format!("li {}, {}", register, n)),
            IrOperand::Const(IrConst::U32(n)) => self.emit(format!("li {}, {}", register, n)),
            IrOperand::Const(IrConst::U64(n)) => self.emit(format!("li {}, {}", register, n)),
            IrOperand::Const(IrConst::Bool(b)) => self.emit(format!("li {}, {}", register, if *b { 1 } else { 0 })),
            IrOperand::Const(value) => {
                if let Some(bytes) = fixed_byte_const_bytes(value) {
                    let label = self.const_data_label_for_bytes(bytes);
                    self.emit(format!("la {}, {}", register, label));
                } else {
                    self.emit(format!("li {}, 0", register));
                }
            }
            IrOperand::Var(v) => self.emit_stack_load(register, v.id * 8),
        }
    }

    /// consume
    fn emit_consume(&mut self, operand: &IrOperand) -> Result<()> {
        self.emit("# consume");
        if let IrOperand::Var(var) = operand {
            if self.consume_indices.contains_key(&var.id) {
                self.emit("# cellscript abi: consumed input pointer retained for verifier field checks");
                return Ok(());
            }
            // Consume a local variable: the actual LOAD_CELL input data loading
            // already happened in the action prelude (generate_consume).
            // Here we only zero out the local binding to enforce linear ownership.
            self.emit_stack_store("zero", var.id * 8);
            return Ok(());
        }
        // Non-Var consume: this should not happen in valid IR, but fail with
        // a specific error code instead of blocking ELF emission.
        self.emit("# cellscript abi: fail closed because consume operand is not a variable");
        self.emit_fail(CellScriptRuntimeError::ConsumeInvalidOperand);
        Ok(())
    }

    /// create
    fn emit_create(&mut self, dest: &IrVar, pattern: &CreatePattern) -> Result<()> {
        let Some((source, output_index)) = self.resolved_cell_location_for_local(dest.id) else {
            self.emit_fail(CellScriptRuntimeError::CellLoadFailed);
            return Ok(());
        };
        self.cell_locations_by_local.insert(dest.id, (source, output_index));
        if pattern.operation == "output" {
            self.emit(format!("# constrain named output {}", pattern.ty));
            for (field, value) in &pattern.fields {
                match value {
                    IrOperand::Const(IrConst::U64(n)) => self.emit(format!("#   field {} = {}", field, n)),
                    IrOperand::Const(IrConst::Bool(b)) => self.emit(format!("#   field {} = {}", field, b)),
                    IrOperand::Var(var) => self.emit(format!("#   field {} <- {}", field, var.name)),
                    _ => self.emit(format!("#   field {} <- <value>", field)),
                }
            }
            if pattern.lock.is_some() {
                self.emit("#   with_lock <expr>");
            }
            if let Some(var_id) = self.output_param_ids.get(&pattern.binding).copied() {
                let Some(size_offset) = self.cell_buffer_size_offsets.get(&var_id).copied() else {
                    self.emit_fail(CellScriptRuntimeError::AssertionFailed);
                    return Ok(());
                };
                let Some(buffer_offset) = self.cell_buffer_offsets.get(&var_id).copied() else {
                    self.emit_fail(CellScriptRuntimeError::AssertionFailed);
                    return Ok(());
                };
                if pattern.fields.is_empty() {
                    self.emit_state_transition_check(pattern, size_offset, buffer_offset);
                } else if self.can_verify_create_output_fields(pattern) {
                    self.emit_create_output_checks_at(pattern, size_offset, buffer_offset);
                } else {
                    self.emit("# cellscript abi: ordered named output field verification incomplete");
                    self.emit("# cellscript abi: fail closed because the output state is not fully verified");
                    self.emit_fail(CellScriptRuntimeError::AssertionFailed);
                    return Ok(());
                }
                if let Some(lock) = &pattern.lock
                    && !(self.can_verify_output_lock(pattern) && self.emit_output_lock_hash_check(source, output_index, lock))
                {
                    self.emit("# cellscript abi: output lock verification incomplete for this named output");
                    self.emit("# cellscript abi: fail closed because the output lock is not fully verified");
                    self.emit_fail(CellScriptRuntimeError::EntryWitnessMagicMismatch);
                    return Ok(());
                }
            } else {
                self.emit_fail(CellScriptRuntimeError::AssertionFailed);
                return Ok(());
            }
            self.emit(format!("li t0, {}", output_index));
            self.emit_stack_store("t0", dest.id * 8);
            self.next_virtual_output = self.next_virtual_output.max(output_index + 1);
            return Ok(());
        }

        self.generate_create(pattern, output_index, false, false)?;
        self.emit(format!("# create {}", pattern.ty));
        for (field, value) in &pattern.fields {
            match value {
                IrOperand::Const(IrConst::U64(n)) => self.emit(format!("#   field {} = {}", field, n)),
                IrOperand::Const(IrConst::Bool(b)) => self.emit(format!("#   field {} = {}", field, b)),
                IrOperand::Var(var) => self.emit(format!("#   field {} <- {}", field, var.name)),
                _ => self.emit(format!("#   field {} <- <value>", field)),
            }
        }
        if pattern.lock.is_some() {
            self.emit("#   with_lock <expr>");
        }
        self.emit(format!("li t0, {}", output_index));
        self.emit_stack_store("t0", dest.id * 8);
        self.next_virtual_output = self.next_virtual_output.max(output_index + 1);
        Ok(())
    }

    fn emit_create_unique_identity_check(&mut self, output_index: usize, pattern: &CreatePattern, identity: &IrIdentityPolicy) {
        let (output_source, output_index) = self.require_output_slot(&pattern.binding, output_index);
        self.emit(format!(
            "# cellscript abi: create_unique identity policy {} for Output#{}",
            identity_policy_label(identity),
            output_index
        ));
        match identity {
            IrIdentityPolicy::None => {}
            IrIdentityPolicy::CkbTypeId => {
                self.emit_output_type_hash_present_check(output_source, output_index, "create_unique_ckb_type_id_output_type_hash");
            }
            IrIdentityPolicy::Field(field) => {
                self.emit_create_unique_field_identity_anchor(output_index, pattern, field);
            }
            IrIdentityPolicy::ScriptArgs => {
                self.emit_cell_field_hash_equality(CellFieldHashCheck {
                    left: CellFieldHashLocation {
                        reason: "create_unique_group_input_lock_hash",
                        source: CKB_SOURCE_GROUP_INPUT,
                        index: 0,
                    },
                    right: CellFieldHashLocation {
                        reason: "create_unique_output_lock_hash",
                        source: output_source,
                        index: output_index,
                    },
                    cell_field: CKB_CELL_FIELD_LOCK_HASH,
                    field_name: "LockHash",
                    detail: "create_unique script_args identity anchor",
                    error: CellScriptRuntimeError::LockHashPreservationMismatch,
                });
            }
            IrIdentityPolicy::SingletonType => {
                self.emit_cell_field_hash_equality(CellFieldHashCheck {
                    left: CellFieldHashLocation {
                        reason: "create_unique_group_input_type_hash",
                        source: CKB_SOURCE_GROUP_INPUT,
                        index: 0,
                    },
                    right: CellFieldHashLocation {
                        reason: "create_unique_output_type_hash",
                        source: output_source,
                        index: output_index,
                    },
                    cell_field: CKB_CELL_FIELD_TYPE_HASH,
                    field_name: "TypeHash",
                    detail: "create_unique singleton_type identity anchor",
                    error: CellScriptRuntimeError::TypeHashMismatch,
                });
            }
        }
    }

    fn emit_create_unique_field_identity_anchor(&mut self, output_index: usize, pattern: &CreatePattern, field: &str) {
        let (output_source, output_index) = self.require_output_slot(&pattern.binding, output_index);
        let Some(layout) = self.type_layouts.get(&pattern.ty).and_then(|fields| fields.get(field)).cloned() else {
            self.emit(format!(
                "# cellscript abi: fail closed because create_unique identity field {}.{} has no layout",
                pattern.ty, field
            ));
            self.emit_fail(CellScriptRuntimeError::AssertionFailed);
            return;
        };
        let Some(width) = layout_fixed_byte_width(&layout) else {
            self.emit(format!(
                "# cellscript abi: fail closed because create_unique identity field {}.{} is not fixed-width",
                pattern.ty, field
            ));
            self.emit_fail(CellScriptRuntimeError::DynamicFieldValueMismatch);
            return;
        };
        let output_size_offset = self.runtime_scratch_size_offset();
        let output_buffer_offset = self.runtime_scratch_buffer_offset();
        self.emit_load_cell_data_syscall("create_unique_identity_field", output_source, output_index);
        self.emit_return_on_syscall_error(CellScriptRuntimeError::CellLoadFailed);
        let output_pointer_offset = self.runtime_expr_temp_offset(0);
        let output_len_offset = self.runtime_expr_temp_offset(1);
        let context = format!("create_unique identity field {}.{}", pattern.ty, field);
        if self.type_fixed_sizes.contains_key(&pattern.ty) {
            self.emit_loaded_fixed_field_pointer_to_stack(
                output_size_offset,
                output_buffer_offset,
                &layout,
                width,
                &context,
                output_pointer_offset,
            );
        } else if let Some(field_count) = self.type_layouts.get(&pattern.ty).map(|fields| fields.len()) {
            self.emit_dynamic_fixed_field_pointer_to_stack(
                output_size_offset,
                output_buffer_offset,
                &layout,
                field_count,
                width,
                &context,
                output_pointer_offset,
                output_len_offset,
            );
        } else {
            self.emit_fail(CellScriptRuntimeError::AssertionFailed);
            return;
        }
        self.emit(format!(
            "# cellscript abi: create_unique field identity anchored by verified Output#{} {}.{} size={}",
            output_index, pattern.ty, field, width
        ));
    }

    fn emit_replace_unique_identity_check(
        &mut self,
        output_index: usize,
        operand: &IrOperand,
        pattern: &CreatePattern,
        identity: &IrIdentityPolicy,
    ) {
        let (output_source, output_index) = self.require_output_slot(&pattern.binding, output_index);
        self.emit(format!(
            "# cellscript abi: replace_unique identity policy {} for Output#{}",
            identity_policy_label(identity),
            output_index
        ));
        let Some((input_source, input_index)) = self.operand_cell_location(operand) else {
            self.emit_fail(CellScriptRuntimeError::CellLoadFailed);
            return;
        };
        match identity {
            IrIdentityPolicy::None => {}
            IrIdentityPolicy::CkbTypeId | IrIdentityPolicy::SingletonType => {
                self.emit_cell_field_hash_equality(CellFieldHashCheck {
                    left: CellFieldHashLocation { reason: "replace_unique_input_type_hash", source: input_source, index: input_index },
                    right: CellFieldHashLocation {
                        reason: "replace_unique_output_type_hash",
                        source: output_source,
                        index: output_index,
                    },
                    cell_field: CKB_CELL_FIELD_TYPE_HASH,
                    field_name: "TypeHash",
                    detail: "replace_unique type identity preservation",
                    error: CellScriptRuntimeError::TypeHashMismatch,
                });
            }
            IrIdentityPolicy::ScriptArgs => {
                self.emit_cell_field_hash_equality(CellFieldHashCheck {
                    left: CellFieldHashLocation { reason: "replace_unique_input_lock_hash", source: input_source, index: input_index },
                    right: CellFieldHashLocation {
                        reason: "replace_unique_output_lock_hash",
                        source: output_source,
                        index: output_index,
                    },
                    cell_field: CKB_CELL_FIELD_LOCK_HASH,
                    field_name: "LockHash",
                    detail: "replace_unique script_args identity preservation",
                    error: CellScriptRuntimeError::LockHashPreservationMismatch,
                });
            }
            IrIdentityPolicy::Field(field) => {
                self.emit_replace_unique_field_identity_check(output_index, operand, pattern, field);
            }
        }
    }

    fn emit_replace_unique_field_identity_check(
        &mut self,
        output_index: usize,
        operand: &IrOperand,
        pattern: &CreatePattern,
        field: &str,
    ) {
        let (output_source, output_index) = self.require_output_slot(&pattern.binding, output_index);
        let input_var = match operand {
            IrOperand::Var(var) => var,
            _ => {
                self.emit("# cellscript abi: fail closed because replace_unique identity input is not a cell variable");
                self.emit_fail(CellScriptRuntimeError::DestroyInvalidOperand);
                return;
            }
        };
        let (Some(input_size_offset), Some(input_buffer_offset)) =
            (self.cell_buffer_size_offsets.get(&input_var.id).copied(), self.cell_buffer_offsets.get(&input_var.id).copied())
        else {
            self.emit("# cellscript abi: fail closed because replace_unique identity input cell data is unavailable");
            self.emit_fail(CellScriptRuntimeError::CellLoadFailed);
            return;
        };
        let Some(layout) = self.type_layouts.get(&pattern.ty).and_then(|fields| fields.get(field)).cloned() else {
            self.emit(format!(
                "# cellscript abi: fail closed because replace_unique identity field {}.{} has no layout",
                pattern.ty, field
            ));
            self.emit_fail(CellScriptRuntimeError::AssertionFailed);
            return;
        };
        let Some(width) = layout_fixed_byte_width(&layout) else {
            self.emit(format!(
                "# cellscript abi: fail closed because replace_unique identity field {}.{} is not fixed-width",
                pattern.ty, field
            ));
            self.emit_fail(CellScriptRuntimeError::DynamicFieldValueMismatch);
            return;
        };

        let output_size_offset = self.runtime_scratch_size_offset();
        let output_buffer_offset = self.runtime_scratch_buffer_offset();
        self.emit_load_cell_data_syscall("replace_unique_identity_field_output", output_source, output_index);
        self.emit_return_on_syscall_error(CellScriptRuntimeError::CellLoadFailed);
        let input_pointer_offset = self.runtime_expr_temp_offset(0);
        let input_len_offset = self.runtime_expr_temp_offset(1);
        let output_pointer_offset = self.runtime_expr_temp_offset(2);
        let output_len_offset = self.runtime_expr_temp_offset(3);
        let input_context = format!("replace_unique input identity field {}.{}", pattern.ty, field);
        let output_context = format!("replace_unique output identity field {}.{}", pattern.ty, field);
        if self.type_fixed_sizes.contains_key(&pattern.ty) {
            self.emit_loaded_fixed_field_pointer_to_stack(
                input_size_offset,
                input_buffer_offset,
                &layout,
                width,
                &input_context,
                input_pointer_offset,
            );
            self.emit_loaded_fixed_field_pointer_to_stack(
                output_size_offset,
                output_buffer_offset,
                &layout,
                width,
                &output_context,
                output_pointer_offset,
            );
        } else if let Some(field_count) = self.type_layouts.get(&pattern.ty).map(|fields| fields.len()) {
            self.emit_dynamic_fixed_field_pointer_to_stack(
                input_size_offset,
                input_buffer_offset,
                &layout,
                field_count,
                width,
                &input_context,
                input_pointer_offset,
                input_len_offset,
            );
            self.emit_dynamic_fixed_field_pointer_to_stack(
                output_size_offset,
                output_buffer_offset,
                &layout,
                field_count,
                width,
                &output_context,
                output_pointer_offset,
                output_len_offset,
            );
        } else {
            self.emit_fail(CellScriptRuntimeError::AssertionFailed);
            return;
        }
        self.emit_fixed_pointer_equality(
            input_pointer_offset,
            output_pointer_offset,
            width,
            &format!("replace_unique identity field {}.{} Input == Output#{}", pattern.ty, field, output_index),
            CellScriptRuntimeError::DynamicFieldValueMismatch,
        );
    }

    /// create_unique
    fn emit_create_unique(&mut self, dest: &IrVar, pattern: &CreatePattern, identity: &IrIdentityPolicy) -> Result<()> {
        let Some((source, output_index)) = self.resolved_cell_location_for_local(dest.id) else {
            self.emit_fail(CellScriptRuntimeError::CellLoadFailed);
            return Ok(());
        };
        self.cell_locations_by_local.insert(dest.id, (source, output_index));
        self.generate_create(pattern, output_index, false, false)?;
        self.emit_create_unique_identity_check(output_index, pattern, identity);
        self.emit(format!("# create_unique {} identity={}", pattern.ty, identity_policy_label(identity)));
        for (field, value) in &pattern.fields {
            match value {
                IrOperand::Const(IrConst::U64(n)) => self.emit(format!("#   field {} = {}", field, n)),
                IrOperand::Const(IrConst::Bool(b)) => self.emit(format!("#   field {} = {}", field, b)),
                IrOperand::Var(var) => self.emit(format!("#   field {} <- {}", field, var.name)),
                _ => self.emit(format!("#   field {} <- <value>", field)),
            }
        }
        if pattern.lock.is_some() {
            self.emit("#   with_lock <expr>");
        }
        self.emit(format!("li t0, {}", output_index));
        self.emit_stack_store("t0", dest.id * 8);
        self.next_virtual_output = self.next_virtual_output.max(output_index + 1);
        Ok(())
    }

    /// replace_unique
    fn emit_replace_unique(
        &mut self,
        dest: &IrVar,
        operand: &IrOperand,
        pattern: &CreatePattern,
        identity: &IrIdentityPolicy,
    ) -> Result<()> {
        let Some((source, output_index)) = self.resolved_cell_location_for_local(dest.id) else {
            self.emit_fail(CellScriptRuntimeError::CellLoadFailed);
            return Ok(());
        };
        self.cell_locations_by_local.insert(dest.id, (source, output_index));
        self.emit(format!("# replace_unique {} identity={}", pattern.ty, identity_policy_label(identity)));
        self.emit_operand_comment("input", operand);
        for (field, value) in &pattern.fields {
            match value {
                IrOperand::Const(IrConst::U64(n)) => self.emit(format!("#   field {} = {}", field, n)),
                IrOperand::Const(IrConst::Bool(b)) => self.emit(format!("#   field {} = {}", field, b)),
                IrOperand::Var(var) => self.emit(format!("#   field {} <- {}", field, var.name)),
                _ => self.emit(format!("#   field {} <- <value>", field)),
            }
        }
        // replace_unique is a consume + create with identity preservation.
        // The output occupies a virtual output slot, similar to transfer.
        self.generate_create(pattern, output_index, false, false)?;
        self.emit_replace_unique_identity_check(output_index, operand, pattern, identity);
        if self.emit_verified_operation_output_handle(dest, "replace_unique") {
            return Ok(());
        }
        self.emit(format!("# cellscript abi: replace_unique output handle Output#{}", output_index));
        self.emit(format!("li t0, {}", output_index));
        self.emit_stack_store("t0", dest.id * 8);
        self.next_virtual_output = self.next_virtual_output.max(output_index + 1);
        Ok(())
    }

    /// transfer
    fn emit_transfer(&mut self, dest: &IrVar, operand: &IrOperand, to: &IrOperand) -> Result<()> {
        self.emit("# transfer");
        self.emit_operand_comment("asset", operand);
        self.emit_operand_comment("to", to);
        if self.emit_verified_operation_output_handle(dest, "transfer") {
            return Ok(());
        }
        if let Some(output_index) = self.operation_output_indices.get(&dest.id).copied() {
            self.emit(format!("# cellscript abi: transfer output handle Output#{} (unverified)", output_index));
            self.emit(format!("li t0, {}", output_index));
            self.emit_stack_store("t0", dest.id * 8);
            self.next_virtual_output = self.next_virtual_output.max(output_index + 1);
            return Ok(());
        }
        self.emit("# cellscript abi: fail closed because transfer output relation is unknown");
        self.emit_fail(CellScriptRuntimeError::DestroyInvalidOperand);
        Ok(())
    }

    /// claim
    fn emit_claim(&mut self, dest: &IrVar, receipt: &IrOperand) -> Result<()> {
        self.emit("# claim");
        self.emit_operand_comment("receipt", receipt);
        if self.emit_verified_operation_output_handle(dest, "claim") {
            return Ok(());
        }
        if let Some(output_index) = self.operation_output_indices.get(&dest.id).copied() {
            self.emit(format!("# cellscript abi: claim output handle Output#{} (unverified)", output_index));
            self.emit(format!("li t0, {}", output_index));
            self.emit_stack_store("t0", dest.id * 8);
            self.next_virtual_output = self.next_virtual_output.max(output_index + 1);
            return Ok(());
        }
        self.emit("# cellscript abi: fail closed because claim output relation is unknown");
        self.emit_fail(CellScriptRuntimeError::DestroyInvalidOperand);
        Ok(())
    }

    /// settle
    fn emit_settle(&mut self, dest: &IrVar, operand: &IrOperand) -> Result<()> {
        self.emit("# settle");
        self.emit_operand_comment("value", operand);
        if self.emit_verified_operation_output_handle(dest, "settle") {
            return Ok(());
        }
        if let Some(output_index) = self.operation_output_indices.get(&dest.id).copied() {
            self.emit(format!("# cellscript abi: settle output handle Output#{} (unverified)", output_index));
            self.emit(format!("li t0, {}", output_index));
            self.emit_stack_store("t0", dest.id * 8);
            self.next_virtual_output = self.next_virtual_output.max(output_index + 1);
            return Ok(());
        }
        self.emit("# cellscript abi: fail closed because settle output relation is unknown");
        self.emit_fail(CellScriptRuntimeError::DestroyInvalidOperand);
        Ok(())
    }

    fn emit_verified_operation_output_handle(&mut self, dest: &IrVar, operation: &str) -> bool {
        if !self.verified_operation_outputs.contains(&dest.id) {
            return false;
        }
        let output_index = self.operation_output_indices.get(&dest.id).copied().unwrap_or(self.next_virtual_output);
        self.emit(format!("# cellscript abi: {} output relation verified by prelude Output#{}", operation, output_index));
        self.emit(format!("li t0, {}", output_index));
        self.emit_stack_store("t0", dest.id * 8);
        self.next_virtual_output = self.next_virtual_output.max(output_index + 1);
        true
    }

    /// destroy
    fn emit_destroy(&mut self, operand: &IrOperand) -> Result<()> {
        self.emit("# destroy");
        if let IrOperand::Var(_) = operand {
            self.emit_operand_comment("destroyed input retained for verifier field checks", operand);
            self.emit("# cellscript abi: destroy consumed input is checked by Output absence scan");
            self.emit("# cellscript abi: retain consumed input pointer for post-destroy output verification");
            return Ok(());
        }
        // Non-Var destroy: this should not happen in valid IR, fail with specific error.
        self.emit("# cellscript abi: fail closed because destroy operand is not a variable");
        self.emit_fail(CellScriptRuntimeError::ConsumeInvalidOperand);
        Ok(())
    }

    fn emit_operand_comment(&mut self, label: &str, operand: &IrOperand) {
        let rendered = match operand {
            IrOperand::Var(var) => format!("{}: {}", label, var.name),
            IrOperand::Const(IrConst::U64(n)) => format!("{}: {}", label, n),
            IrOperand::Const(IrConst::Bool(b)) => format!("{}: {}", label, b),
            IrOperand::Const(IrConst::Address(_)) => format!("{}: <address>", label),
            IrOperand::Const(IrConst::Hash(_)) => format!("{}: <hash>", label),
            IrOperand::Const(IrConst::Array(items)) => format!("{}: <array:{}>", label, items.len()),
            IrOperand::Const(_) => format!("{}: <const>", label),
        };
        self.emit(format!("#   {}", rendered));
    }

    fn static_length(&self, operand: &IrOperand) -> Option<usize> {
        match operand {
            IrOperand::Var(var) => Self::static_length_from_type(&var.ty),
            IrOperand::Const(IrConst::Array(items)) => Some(items.len()),
            _ => None,
        }
    }

    fn static_length_from_type(ty: &IrType) -> Option<usize> {
        match ty {
            IrType::Array(_, size) => Some(*size),
            IrType::Ref(inner) | IrType::MutRef(inner) => Self::static_length_from_type(inner),
            _ => None,
        }
    }
}

/// Preserve the authoritative stack value while avoiding an immediately
/// redundant memory read. This deliberately crosses comments only, never a
/// label, directive, branch, call, or other instruction.
fn eliminate_immediate_stack_reloads(assembly: &mut [String]) {
    for store_index in 0..assembly.len() {
        let Some((source, offset)) = stack_slot_access(&assembly[store_index], "sd") else {
            continue;
        };
        let Some(load_index) = ((store_index + 1)..assembly.len()).find(|index| {
            let line = assembly[*index].trim();
            !line.is_empty() && !line.starts_with('#')
        }) else {
            continue;
        };
        let Some((dest, load_offset)) = stack_slot_access(&assembly[load_index], "ld") else {
            continue;
        };
        if offset != load_offset {
            continue;
        }
        assembly[load_index] = if source == dest { String::new() } else { format!("    mv {dest}, {source}") };
    }
}

fn stack_slot_access(line: &str, expected_opcode: &str) -> Option<(String, i64)> {
    let clean = strip_comment(line)?;
    let mut parts = clean.splitn(2, char::is_whitespace);
    if parts.next()? != expected_opcode {
        return None;
    }
    let args = parts.next()?.split(',').map(str::trim).collect::<Vec<_>>();
    if args.len() != 2 || parse_register(args[0]).is_err() {
        return None;
    }
    let (offset, base) = memory_operand_offset_and_base(args[1])?;
    (base == "sp").then(|| (args[0].to_string(), offset))
}

fn with_codegen_code(error: CompileError, code: &'static str) -> CompileError {
    if error.code.is_some() {
        error
    } else {
        error.with_code(code)
    }
}

pub fn analyze_backend_shape(assembly: &str) -> Result<BackendShapeMetrics> {
    let lines = assembly.lines().map(str::to_string).collect::<Vec<_>>();
    MachineLayoutPlan::build(&lines).map(|plan| plan.metrics.into())
}

fn entry_witness_payload_layout(
    params: &[IrParam],
    runtime_bound_param_indices: &BTreeSet<usize>,
    bounded_plan_param_indices: &BTreeSet<usize>,
    enum_layouts: &HashMap<String, IrEnumLayout>,
) -> Vec<EntryWitnessPayloadArg> {
    params
        .iter()
        .enumerate()
        .map(|(index, param)| {
            if !entry_param_consumes_witness_payload(param, index, runtime_bound_param_indices) {
                EntryWitnessPayloadArg { width: 0, schema_dynamic: false, unsupported: false }
            } else if bounded_plan_param_indices.contains(&index) {
                EntryWitnessPayloadArg { width: 4, schema_dynamic: true, unsupported: false }
            } else if is_bounded_collection_type(&param.ty) {
                EntryWitnessPayloadArg { width: 0, schema_dynamic: false, unsupported: true }
            } else if let Some(layout) = match &param.ty {
                IrType::Named(name) => enum_layouts.get(name).filter(|layout| layout.has_payload()),
                _ => None,
            } {
                EntryWitnessPayloadArg { width: layout.encoded_size, schema_dynamic: false, unsupported: false }
            } else if entry_witness_dynamic_schema_param(&param.ty) {
                EntryWitnessPayloadArg { width: 4, schema_dynamic: true, unsupported: false }
            } else if let Some(width) =
                fixed_byte_pointer_param_width(&param.ty).or_else(|| fixed_aggregate_pointer_param_width(&param.ty))
            {
                EntryWitnessPayloadArg { width, schema_dynamic: false, unsupported: false }
            } else if let Some(width) = entry_witness_register_param_width(&param.ty) {
                EntryWitnessPayloadArg { width, schema_dynamic: false, unsupported: false }
            } else {
                EntryWitnessPayloadArg { width: 0, schema_dynamic: false, unsupported: true }
            }
        })
        .collect()
}

fn is_bounded_collection_type(ty: &IrType) -> bool {
    matches!(
        ty,
        IrType::Named(name)
            if name.starts_with("BoundedCellSet<") || name.starts_with("BoundedList<")
    )
}

fn entry_param_consumes_witness_payload(param: &IrParam, index: usize, runtime_bound_param_indices: &BTreeSet<usize>) -> bool {
    param.source != ParamSource::LockArgs
        && !runtime_bound_param_indices.contains(&index)
        && !matches!(param.ty, IrType::Ref(_) | IrType::MutRef(_))
}

fn entry_witness_dynamic_schema_param(ty: &IrType) -> bool {
    fixed_byte_pointer_param_width(ty).is_none()
        && fixed_aggregate_pointer_param_width(ty).is_none()
        && entry_witness_register_param_width(ty).is_none()
}

fn entry_witness_register_param_width(ty: &IrType) -> Option<usize> {
    fixed_register_width(ty, type_static_length(ty)).or_else(|| match ty {
        // The source spelling `()` is lowered as an empty tuple. It has the
        // same zero-byte entry encoding as the internal Unit type.
        IrType::Tuple(items) if items.is_empty() => Some(0),
        IrType::Array(_, _) | IrType::Tuple(_) => type_static_length(ty).filter(|width| (1..=8).contains(width)),
        IrType::Unit => Some(0),
        _ => None,
    })
}

fn named_type_name(ty: &IrType) -> Option<&str> {
    match ty {
        IrType::Named(name) => Some(name.as_str()),
        IrType::Ref(inner) | IrType::MutRef(inner) => named_type_name(inner),
        _ => None,
    }
}

fn consumed_operand_var(instruction: &IrInstruction) -> Option<&IrVar> {
    let operand = match instruction {
        IrInstruction::Consume { operand }
        | IrInstruction::Transfer { operand, .. }
        | IrInstruction::Destroy { operand, .. }
        | IrInstruction::Settle { operand, .. }
        | IrInstruction::ReplaceUnique { operand, .. } => operand,
        IrInstruction::Claim { receipt, .. } => receipt,
        _ => return None,
    };
    match operand {
        IrOperand::Var(var) if named_type_name(&var.ty).is_some() => Some(var),
        _ => None,
    }
}
