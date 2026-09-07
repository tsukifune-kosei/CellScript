pub mod ckb_protocols;
pub mod collections;
pub mod signature;

use crate::{ckb_abi, ckb_blake2b256, ir::IrType, runtime_errors::CellScriptRuntimeError, TargetProfile};

pub struct StdLib;

impl StdLib {
    pub fn functions() -> Vec<StdFunction> {
        vec![
            StdFunction { name: "syscall_load_tx_hash".to_string(), params: vec![], return_type: Some(IrType::Hash) },
            StdFunction { name: "syscall_load_script_hash".to_string(), params: vec![], return_type: Some(IrType::Hash) },
            StdFunction {
                name: "syscall_load_cell".to_string(),
                params: vec![
                    ("index".to_string(), IrType::U64),
                    ("source".to_string(), IrType::U64),
                    ("field".to_string(), IrType::U64),
                ],
                return_type: Some(IrType::U64),
            },
            StdFunction {
                name: "syscall_load_header".to_string(),
                params: vec![
                    ("buffer".to_string(), IrType::U64),
                    ("size".to_string(), IrType::U64),
                    ("offset".to_string(), IrType::U64),
                    ("index".to_string(), IrType::U64),
                    ("source".to_string(), IrType::U64),
                ],
                return_type: Some(IrType::U64),
            },
            StdFunction {
                name: "syscall_load_input".to_string(),
                params: vec![
                    ("index".to_string(), IrType::U64),
                    ("source".to_string(), IrType::U64),
                    ("field".to_string(), IrType::U64),
                ],
                return_type: Some(IrType::U64),
            },
            StdFunction {
                name: "syscall_load_script".to_string(),
                params: vec![
                    ("buffer".to_string(), IrType::U64),
                    ("size".to_string(), IrType::U64),
                    ("offset".to_string(), IrType::U64),
                ],
                return_type: Some(IrType::U64),
            },
            StdFunction {
                name: "syscall_load_cell_by_field".to_string(),
                params: vec![
                    ("buffer".to_string(), IrType::U64),
                    ("size".to_string(), IrType::U64),
                    ("offset".to_string(), IrType::U64),
                    ("index".to_string(), IrType::U64),
                    ("source".to_string(), IrType::U64),
                    ("field".to_string(), IrType::U64),
                ],
                return_type: Some(IrType::U64),
            },
            StdFunction {
                name: "syscall_load_cell_data".to_string(),
                params: vec![
                    ("buffer".to_string(), IrType::U64),
                    ("size".to_string(), IrType::U64),
                    ("offset".to_string(), IrType::U64),
                    ("index".to_string(), IrType::U64),
                    ("source".to_string(), IrType::U64),
                ],
                return_type: Some(IrType::U64),
            },
            StdFunction {
                name: "syscall_load_witness".to_string(),
                params: vec![("index".to_string(), IrType::U64), ("source".to_string(), IrType::U64)],
                return_type: Some(IrType::U64),
            },
            StdFunction { name: "syscall_current_cycles".to_string(), params: vec![], return_type: Some(IrType::U64) },
            StdFunction {
                name: "syscall_debug_print".to_string(),
                params: vec![("msg".to_string(), IrType::Array(Box::new(IrType::U8), 0))],
                return_type: None,
            },
            StdFunction {
                name: "math_min".to_string(),
                params: vec![("a".to_string(), IrType::U64), ("b".to_string(), IrType::U64)],
                return_type: Some(IrType::U64),
            },
            StdFunction {
                name: "math_max".to_string(),
                params: vec![("a".to_string(), IrType::U64), ("b".to_string(), IrType::U64)],
                return_type: Some(IrType::U64),
            },
            StdFunction {
                name: "math_isqrt".to_string(),
                params: vec![("n".to_string(), IrType::U64)],
                return_type: Some(IrType::U64),
            },
            StdFunction {
                name: "math_abs_diff".to_string(),
                params: vec![("a".to_string(), IrType::U64), ("b".to_string(), IrType::U64)],
                return_type: Some(IrType::U64),
            },
            StdFunction {
                name: "c256_require_product_lte".to_string(),
                params: vec![
                    ("left_amount".to_string(), IrType::U128),
                    ("left_multiplier".to_string(), IrType::U128),
                    ("right_amount".to_string(), IrType::U128),
                    ("right_multiplier".to_string(), IrType::U128),
                ],
                return_type: None,
            },
            StdFunction {
                name: "c256_require_product_eq".to_string(),
                params: vec![
                    ("left_amount".to_string(), IrType::U128),
                    ("left_multiplier".to_string(), IrType::U128),
                    ("right_amount".to_string(), IrType::U128),
                    ("right_multiplier".to_string(), IrType::U128),
                ],
                return_type: None,
            },
            StdFunction {
                name: "c256_require_sum2_products_lte".to_string(),
                params: vec![
                    ("left_amount_a".to_string(), IrType::U128),
                    ("left_multiplier_a".to_string(), IrType::U128),
                    ("left_amount_b".to_string(), IrType::U128),
                    ("left_multiplier_b".to_string(), IrType::U128),
                    ("right_amount_a".to_string(), IrType::U128),
                    ("right_multiplier_a".to_string(), IrType::U128),
                    ("right_amount_b".to_string(), IrType::U128),
                    ("right_multiplier_b".to_string(), IrType::U128),
                ],
                return_type: None,
            },
            StdFunction {
                name: "c256_require_sum2_products_eq".to_string(),
                params: vec![
                    ("left_amount_a".to_string(), IrType::U128),
                    ("left_multiplier_a".to_string(), IrType::U128),
                    ("left_amount_b".to_string(), IrType::U128),
                    ("left_multiplier_b".to_string(), IrType::U128),
                    ("right_amount_a".to_string(), IrType::U128),
                    ("right_multiplier_a".to_string(), IrType::U128),
                    ("right_amount_b".to_string(), IrType::U128),
                    ("right_multiplier_b".to_string(), IrType::U128),
                ],
                return_type: None,
            },
            StdFunction { name: "env_current_timepoint".to_string(), params: vec![], return_type: Some(IrType::U64) },
            StdFunction { name: "ckb_header_epoch_number".to_string(), params: vec![], return_type: Some(IrType::U64) },
            StdFunction { name: "ckb_header_epoch_start_block_number".to_string(), params: vec![], return_type: Some(IrType::U64) },
            StdFunction { name: "ckb_header_epoch_length".to_string(), params: vec![], return_type: Some(IrType::U64) },
            StdFunction { name: "ckb_input_since".to_string(), params: vec![], return_type: Some(IrType::U64) },
            StdFunction {
                name: "ckb_since_epoch_absolute".to_string(),
                params: vec![
                    ("number".to_string(), IrType::U64),
                    ("index".to_string(), IrType::U64),
                    ("length".to_string(), IrType::U64),
                ],
                return_type: Some(IrType::U64),
            },
            StdFunction {
                name: "ckb_since_epoch_relative".to_string(),
                params: vec![
                    ("number".to_string(), IrType::U64),
                    ("index".to_string(), IrType::U64),
                    ("length".to_string(), IrType::U64),
                ],
                return_type: Some(IrType::U64),
            },
            StdFunction {
                name: "ckb_since_absolute_epoch".to_string(),
                params: vec![
                    ("number".to_string(), IrType::U64),
                    ("index".to_string(), IrType::U64),
                    ("length".to_string(), IrType::U64),
                ],
                return_type: Some(IrType::Named("AbsoluteEpochSince".to_string())),
            },
            StdFunction {
                name: "ckb_since_relative_epoch".to_string(),
                params: vec![
                    ("number".to_string(), IrType::U64),
                    ("index".to_string(), IrType::U64),
                    ("length".to_string(), IrType::U64),
                ],
                return_type: Some(IrType::Named("RelativeEpochSince".to_string())),
            },
            StdFunction {
                name: "ckb_since_absolute_block".to_string(),
                params: vec![("value".to_string(), IrType::U64)],
                return_type: Some(IrType::Named("AbsoluteBlockSince".to_string())),
            },
            StdFunction {
                name: "ckb_since_relative_block".to_string(),
                params: vec![("value".to_string(), IrType::U64)],
                return_type: Some(IrType::Named("RelativeBlockSince".to_string())),
            },
            StdFunction {
                name: "ckb_since_absolute_timestamp".to_string(),
                params: vec![("seconds".to_string(), IrType::U64)],
                return_type: Some(IrType::Named("AbsoluteTimestampSince".to_string())),
            },
            StdFunction {
                name: "ckb_since_relative_timestamp".to_string(),
                params: vec![("seconds".to_string(), IrType::U64)],
                return_type: Some(IrType::Named("RelativeTimestampSince".to_string())),
            },
            StdFunction {
                name: "ckb_since_decode".to_string(),
                params: vec![("encoded".to_string(), IrType::Named("EncodedSince".to_string()))],
                return_type: Some(IrType::Named("DecodedSince".to_string())),
            },
            StdFunction {
                name: "ckb_since_from_raw_checked".to_string(),
                params: vec![("raw".to_string(), IrType::U64)],
                return_type: Some(IrType::Named("DecodedSince".to_string())),
            },
            StdFunction {
                name: "ckb_since_as_absolute_block".to_string(),
                params: vec![("decoded".to_string(), IrType::Named("DecodedSince".to_string()))],
                return_type: Some(IrType::Named("AbsoluteBlockSince".to_string())),
            },
            StdFunction {
                name: "ckb_since_as_relative_block".to_string(),
                params: vec![("decoded".to_string(), IrType::Named("DecodedSince".to_string()))],
                return_type: Some(IrType::Named("RelativeBlockSince".to_string())),
            },
            StdFunction {
                name: "ckb_since_as_absolute_epoch".to_string(),
                params: vec![("decoded".to_string(), IrType::Named("DecodedSince".to_string()))],
                return_type: Some(IrType::Named("AbsoluteEpochSince".to_string())),
            },
            StdFunction {
                name: "ckb_since_as_relative_epoch".to_string(),
                params: vec![("decoded".to_string(), IrType::Named("DecodedSince".to_string()))],
                return_type: Some(IrType::Named("RelativeEpochSince".to_string())),
            },
            StdFunction {
                name: "ckb_since_as_absolute_timestamp".to_string(),
                params: vec![("decoded".to_string(), IrType::Named("DecodedSince".to_string()))],
                return_type: Some(IrType::Named("AbsoluteTimestampSince".to_string())),
            },
            StdFunction {
                name: "ckb_since_as_relative_timestamp".to_string(),
                params: vec![("decoded".to_string(), IrType::Named("DecodedSince".to_string()))],
                return_type: Some(IrType::Named("RelativeTimestampSince".to_string())),
            },
            StdFunction {
                name: "ckb_since_is_relative".to_string(),
                params: vec![("decoded".to_string(), IrType::Named("DecodedSince".to_string()))],
                return_type: Some(IrType::Bool),
            },
            StdFunction {
                name: "ckb_since_is_disabled".to_string(),
                params: vec![("decoded".to_string(), IrType::Named("DecodedSince".to_string()))],
                return_type: Some(IrType::Bool),
            },
            StdFunction {
                name: "ckb_since_metric".to_string(),
                params: vec![("decoded".to_string(), IrType::Named("DecodedSince".to_string()))],
                return_type: Some(IrType::U64),
            },
            StdFunction {
                name: "ckb_since_value".to_string(),
                params: vec![("decoded".to_string(), IrType::Named("DecodedSince".to_string()))],
                return_type: Some(IrType::U64),
            },
            StdFunction {
                name: "ckb_epoch_duration".to_string(),
                params: vec![("value".to_string(), IrType::U64)],
                return_type: Some(IrType::Named("EpochDuration".to_string())),
            },
            StdFunction {
                name: "ckb_epoch_add".to_string(),
                params: vec![
                    ("epoch".to_string(), IrType::Named("EpochNumber".to_string())),
                    ("duration".to_string(), IrType::Named("EpochDuration".to_string())),
                ],
                return_type: Some(IrType::Named("EpochNumber".to_string())),
            },
            StdFunction {
                name: "ckb_epoch_sub".to_string(),
                params: vec![
                    ("epoch".to_string(), IrType::Named("EpochNumber".to_string())),
                    ("duration".to_string(), IrType::Named("EpochDuration".to_string())),
                ],
                return_type: Some(IrType::Named("EpochNumber".to_string())),
            },
            StdFunction {
                name: "ckb_epoch_duration_to_u64".to_string(),
                params: vec![("duration".to_string(), IrType::Named("EpochDuration".to_string()))],
                return_type: Some(IrType::U64),
            },
            StdFunction {
                name: "ckb_timestamp_millis_to_u64".to_string(),
                params: vec![("timestamp".to_string(), IrType::Named("TimestampMillis".to_string()))],
                return_type: Some(IrType::U64),
            },
            StdFunction { name: "ckb_current_role".to_string(), params: vec![], return_type: Some(IrType::U64) },
            StdFunction {
                name: "ckb_cell_capacity".to_string(),
                params: vec![("source_view".to_string(), IrType::U64)],
                return_type: Some(IrType::U64),
            },
            StdFunction {
                name: "ckb_cell_occupied_capacity".to_string(),
                params: vec![("source_view".to_string(), IrType::U64)],
                return_type: Some(IrType::U64),
            },
            StdFunction {
                name: "ckb_cell_unoccupied_capacity".to_string(),
                params: vec![("source_view".to_string(), IrType::U64)],
                return_type: Some(IrType::U64),
            },
            StdFunction {
                name: "ckb_cell_data_u64_le".to_string(),
                params: vec![("source_view".to_string(), IrType::U64), ("offset".to_string(), IrType::U64)],
                return_type: Some(IrType::U64),
            },
            StdFunction {
                name: "ckb_cell_data_u32_le".to_string(),
                params: vec![("source_view".to_string(), IrType::U64), ("offset".to_string(), IrType::U64)],
                return_type: Some(IrType::U64),
            },
            StdFunction { name: "ckb_current_script_hash".to_string(), params: vec![], return_type: Some(IrType::Hash) },
            StdFunction {
                name: "ckb_cell_lock_hash_low".to_string(),
                params: vec![("source_view".to_string(), IrType::U64)],
                return_type: Some(IrType::U64),
            },
            StdFunction {
                name: "ckb_cell_type_hash_low".to_string(),
                params: vec![("source_view".to_string(), IrType::U64)],
                return_type: Some(IrType::U64),
            },
            StdFunction {
                name: "ckb_cell_lock_hash".to_string(),
                params: vec![("source_view".to_string(), IrType::U64)],
                return_type: Some(IrType::Hash),
            },
            StdFunction {
                name: "ckb_cell_type_hash".to_string(),
                params: vec![("source_view".to_string(), IrType::U64)],
                return_type: Some(IrType::Hash),
            },
            StdFunction {
                name: "ckb_cell_lock_code_hash".to_string(),
                params: vec![("source_view".to_string(), IrType::U64)],
                return_type: Some(IrType::Hash),
            },
            StdFunction {
                name: "ckb_cell_type_code_hash".to_string(),
                params: vec![("source_view".to_string(), IrType::U64)],
                return_type: Some(IrType::Hash),
            },
            StdFunction {
                name: "ckb_cell_lock_hash_type".to_string(),
                params: vec![("source_view".to_string(), IrType::U64)],
                return_type: Some(IrType::U64),
            },
            StdFunction {
                name: "ckb_cell_type_hash_type".to_string(),
                params: vec![("source_view".to_string(), IrType::U64)],
                return_type: Some(IrType::U64),
            },
            StdFunction {
                name: "ckb_cell_lock_args_empty".to_string(),
                params: vec![("source_view".to_string(), IrType::U64)],
                return_type: Some(IrType::Bool),
            },
            StdFunction {
                name: "ckb_cell_type_args_empty".to_string(),
                params: vec![("source_view".to_string(), IrType::U64)],
                return_type: Some(IrType::Bool),
            },
            StdFunction {
                name: "ckb_cell_lock_args_hash".to_string(),
                params: vec![("source_view".to_string(), IrType::U64)],
                return_type: Some(IrType::Hash),
            },
            StdFunction {
                name: "ckb_cell_type_args_hash".to_string(),
                params: vec![("source_view".to_string(), IrType::U64)],
                return_type: Some(IrType::Hash),
            },
            StdFunction {
                name: "ckb_input_out_point_index".to_string(),
                params: vec![("source_view".to_string(), IrType::U64)],
                return_type: Some(IrType::U64),
            },
            StdFunction {
                name: "ckb_input_out_point_tx_hash_low".to_string(),
                params: vec![("source_view".to_string(), IrType::U64)],
                return_type: Some(IrType::U64),
            },
            StdFunction {
                name: "ckb_input_out_point_tx_hash".to_string(),
                params: vec![("source_view".to_string(), IrType::U64)],
                return_type: Some(IrType::Hash),
            },
            StdFunction {
                name: "ckb_require_cell_lock_hash".to_string(),
                params: vec![("source_view".to_string(), IrType::U64), ("expected_hash".to_string(), IrType::Hash)],
                return_type: None,
            },
            StdFunction {
                name: "ckb_require_cell_type_hash".to_string(),
                params: vec![("source_view".to_string(), IrType::U64), ("expected_hash".to_string(), IrType::Hash)],
                return_type: None,
            },
            StdFunction { name: "ckb_require_current_script_args_empty".to_string(), params: vec![], return_type: None },
            StdFunction {
                name: "ckb_require_cell_lock_args_empty".to_string(),
                params: vec![("source_view".to_string(), IrType::U64)],
                return_type: None,
            },
            StdFunction {
                name: "ckb_require_cell_type_args_empty".to_string(),
                params: vec![("source_view".to_string(), IrType::U64)],
                return_type: None,
            },
            StdFunction {
                name: "ckb_require_cell_lock_args_hash".to_string(),
                params: vec![("source_view".to_string(), IrType::U64), ("expected_args_hash".to_string(), IrType::Hash)],
                return_type: None,
            },
            StdFunction {
                name: "ckb_require_cell_type_args_hash".to_string(),
                params: vec![("source_view".to_string(), IrType::U64), ("expected_args_hash".to_string(), IrType::Hash)],
                return_type: None,
            },
            StdFunction {
                name: "ckb_require_cell_lock_args_prefix_hash".to_string(),
                params: vec![("source_view".to_string(), IrType::U64), ("expected_args_hash".to_string(), IrType::Hash)],
                return_type: None,
            },
            StdFunction {
                name: "ckb_require_cell_type_args_prefix_hash".to_string(),
                params: vec![("source_view".to_string(), IrType::U64), ("expected_args_hash".to_string(), IrType::Hash)],
                return_type: None,
            },
            StdFunction {
                name: "ckb_require_cell_lock_args_suffix_hash".to_string(),
                params: vec![("source_view".to_string(), IrType::U64), ("expected_args_hash".to_string(), IrType::Hash)],
                return_type: None,
            },
            StdFunction {
                name: "ckb_require_cell_type_args_suffix_hash".to_string(),
                params: vec![("source_view".to_string(), IrType::U64), ("expected_args_hash".to_string(), IrType::Hash)],
                return_type: None,
            },
            StdFunction {
                name: "ckb_require_cell_lock_script_hash_type".to_string(),
                params: vec![
                    ("source_view".to_string(), IrType::U64),
                    ("expected_code_hash".to_string(), IrType::Hash),
                    ("expected_hash_type".to_string(), IrType::U64),
                ],
                return_type: None,
            },
            StdFunction {
                name: "ckb_require_cell_type_script_hash_type".to_string(),
                params: vec![
                    ("source_view".to_string(), IrType::U64),
                    ("expected_code_hash".to_string(), IrType::Hash),
                    ("expected_hash_type".to_string(), IrType::U64),
                ],
                return_type: None,
            },
            StdFunction {
                name: "ckb_require_input_out_point_tx_hash".to_string(),
                params: vec![("source_view".to_string(), IrType::U64), ("expected_hash".to_string(), IrType::Hash)],
                return_type: None,
            },
            StdFunction {
                name: "ckb_require_input_out_point".to_string(),
                params: vec![
                    ("source_view".to_string(), IrType::U64),
                    ("expected_hash".to_string(), IrType::Hash),
                    ("expected_index".to_string(), IrType::U64),
                ],
                return_type: None,
            },
            StdFunction {
                name: "ckb_require_metapoint_relative".to_string(),
                params: vec![
                    ("base_view".to_string(), IrType::U64),
                    ("related_view".to_string(), IrType::U64),
                    ("relative_distance".to_string(), IrType::I32),
                ],
                return_type: None,
            },
            StdFunction {
                name: "ckb_require_lock_type_metapoint_pairs".to_string(),
                params: vec![("source_view".to_string(), IrType::U64), ("relative_distance".to_string(), IrType::I32)],
                return_type: None,
            },
            StdFunction {
                name: "ckb_require_type_lock_metapoint_pairs".to_string(),
                params: vec![("source_view".to_string(), IrType::U64), ("relative_distance".to_string(), IrType::I32)],
                return_type: None,
            },
            StdFunction {
                name: "ckb_require_lock_type_metapoint_pairs_from_i32_data".to_string(),
                params: vec![("source_view".to_string(), IrType::U64), ("distance_offset".to_string(), IrType::U64)],
                return_type: None,
            },
            StdFunction {
                name: "ckb_require_type_lock_metapoint_pairs_from_i32_data".to_string(),
                params: vec![("source_view".to_string(), IrType::U64), ("distance_offset".to_string(), IrType::U64)],
                return_type: None,
            },
            StdFunction {
                name: "ckb_require_lock_type_metapoint_pairs_from_i32_data_filtered".to_string(),
                params: vec![
                    ("source_view".to_string(), IrType::U64),
                    ("distance_offset".to_string(), IrType::U64),
                    ("expected_related_type_hash".to_string(), IrType::Hash),
                    ("related_data_rule".to_string(), IrType::U64),
                ],
                return_type: None,
            },
            StdFunction {
                name: "ckb_require_type_lock_metapoint_pairs_from_i32_data_filtered".to_string(),
                params: vec![
                    ("source_view".to_string(), IrType::U64),
                    ("distance_offset".to_string(), IrType::U64),
                    ("expected_related_type_hash".to_string(), IrType::Hash),
                    ("related_data_rule".to_string(), IrType::U64),
                ],
                return_type: None,
            },
            StdFunction {
                name: "ckb_require_lock_match_master_out_point_pairs_from_data".to_string(),
                params: vec![
                    ("input_source_view".to_string(), IrType::U64),
                    ("output_source_view".to_string(), IrType::U64),
                    ("action_offset".to_string(), IrType::U64),
                    ("tx_hash_offset".to_string(), IrType::U64),
                    ("index_offset".to_string(), IrType::U64),
                ],
                return_type: None,
            },
            StdFunction {
                name: "dao_accumulated_rate".to_string(),
                params: vec![("header_view".to_string(), IrType::U64)],
                return_type: Some(IrType::U64),
            },
            StdFunction {
                name: "dao_input_accumulated_rate".to_string(),
                params: vec![("input_view".to_string(), IrType::U64)],
                return_type: Some(IrType::U64),
            },
            StdFunction {
                name: "dao_has_dao_type".to_string(),
                params: vec![("source_view".to_string(), IrType::U64)],
                return_type: Some(IrType::Bool),
            },
            StdFunction {
                name: "dao_is_deposit_data".to_string(),
                params: vec![("source_view".to_string(), IrType::U64)],
                return_type: Some(IrType::Bool),
            },
            StdFunction {
                name: "dao_is_withdrawal_request_data".to_string(),
                params: vec![("source_view".to_string(), IrType::U64)],
                return_type: Some(IrType::Bool),
            },
            StdFunction {
                name: "dao_require_header_dep_for_input".to_string(),
                params: vec![("input_view".to_string(), IrType::U64), ("header_view".to_string(), IrType::U64)],
                return_type: None,
            },
            StdFunction {
                name: "dao_require_input_since_at_least".to_string(),
                params: vec![("input_view".to_string(), IrType::U64), ("required_since".to_string(), IrType::U64)],
                return_type: None,
            },
            StdFunction {
                name: "dao_require_input_relative_epoch_since_at_least".to_string(),
                params: vec![
                    ("input_view".to_string(), IrType::U64),
                    ("number".to_string(), IrType::U64),
                    ("index".to_string(), IrType::U64),
                    ("length".to_string(), IrType::U64),
                ],
                return_type: None,
            },
            StdFunction {
                name: "xudt_amount_low".to_string(),
                params: vec![("source_view".to_string(), IrType::U64)],
                return_type: Some(IrType::U64),
            },
            StdFunction {
                name: "xudt_require_owner_mode_type_args".to_string(),
                params: vec![
                    ("source_view".to_string(), IrType::U64),
                    ("owner_hash".to_string(), IrType::Hash),
                    ("flags".to_string(), IrType::U64),
                ],
                return_type: None,
            },
            StdFunction {
                name: "xudt_require_owner_mode_type_args_current_script".to_string(),
                params: vec![("source_view".to_string(), IrType::U64), ("flags".to_string(), IrType::U64)],
                return_type: None,
            },
            StdFunction { name: "xudt_require_group_amount_conserved".to_string(), params: vec![], return_type: None },
            StdFunction {
                name: "xudt_require_group_amount_minted".to_string(),
                params: vec![("delta".to_string(), IrType::U128)],
                return_type: None,
            },
            StdFunction {
                name: "xudt_require_group_amount_burned".to_string(),
                params: vec![("delta".to_string(), IrType::U128)],
                return_type: None,
            },
            StdFunction { name: "env_remaining_cycles".to_string(), params: vec![], return_type: Some(IrType::U64) },
        ]
    }

    pub fn is_std_function(name: &str) -> bool {
        Self::functions().iter().any(|f| f.name == name)
    }

    pub fn get_function(name: &str) -> Option<StdFunction> {
        Self::functions().into_iter().find(|f| f.name == name)
    }

    pub fn generate_assembly() -> String {
        Self::generate_assembly_for_target_profile(TargetProfile::Ckb)
    }

    pub fn generate_assembly_for_target_profile(target_profile: TargetProfile) -> String {
        let mut asm = String::new();

        asm.push_str("# CellScript Standard Library\n\n");
        asm.push_str(".section .text\n\n");

        asm.push_str(&Self::generate_syscalls(target_profile));

        asm.push_str(&Self::generate_math());

        asm.push_str(&Self::generate_env(target_profile));

        asm
    }

    fn generate_syscalls(target_profile: TargetProfile) -> String {
        let mut asm = String::new();

        asm.push_str(&format!("# Syscall: load_tx_hash ({})\n", ckb_abi::syscall::LOAD_TX_HASH));
        asm.push_str(".global __syscall_load_tx_hash\n");
        asm.push_str("__syscall_load_tx_hash:\n");
        asm.push_str("    addi sp, sp, -16\n");
        asm.push_str("    sd ra, 8(sp)\n");
        asm.push_str(&format!("    li a7, {}\n", ckb_abi::syscall::LOAD_TX_HASH));
        asm.push_str("    ecall\n");
        asm.push_str("    ld ra, 8(sp)\n");
        asm.push_str("    addi sp, sp, 16\n");
        asm.push_str("    ret\n\n");

        asm.push_str(&format!("# Syscall: load_script_hash ({})\n", ckb_abi::syscall::LOAD_SCRIPT_HASH));
        asm.push_str(".global __syscall_load_script_hash\n");
        asm.push_str("__syscall_load_script_hash:\n");
        asm.push_str("    addi sp, sp, -16\n");
        asm.push_str("    sd ra, 8(sp)\n");
        asm.push_str(&format!("    li a7, {}\n", ckb_abi::syscall::LOAD_SCRIPT_HASH));
        asm.push_str("    ecall\n");
        asm.push_str("    ld ra, 8(sp)\n");
        asm.push_str("    addi sp, sp, 16\n");
        asm.push_str("    ret\n\n");

        asm.push_str(&format!("# Syscall: load_cell ({})\n", ckb_abi::syscall::LOAD_CELL));
        asm.push_str(".global __syscall_load_cell\n");
        asm.push_str("__syscall_load_cell:\n");
        asm.push_str("    addi sp, sp, -16\n");
        asm.push_str("    sd ra, 8(sp)\n");
        asm.push_str(&format!("    li a7, {}\n", ckb_abi::syscall::LOAD_CELL));
        asm.push_str("    # a0 = index, a1 = source, a2 = field\n");
        asm.push_str("    ecall\n");
        asm.push_str("    ld ra, 8(sp)\n");
        asm.push_str("    addi sp, sp, 16\n");
        asm.push_str("    ret\n\n");

        asm.push_str(&format!("# Syscall: load_header ({})\n", ckb_abi::syscall::LOAD_HEADER));
        asm.push_str(".global __syscall_load_header\n");
        asm.push_str("__syscall_load_header:\n");
        asm.push_str("    addi sp, sp, -16\n");
        asm.push_str("    sd ra, 8(sp)\n");
        asm.push_str(&format!("    li a7, {}\n", ckb_abi::syscall::LOAD_HEADER));
        asm.push_str("    # a0 = buffer, a1 = size pointer, a2 = offset, a3 = index, a4 = source\n");
        asm.push_str("    ecall\n");
        asm.push_str("    ld ra, 8(sp)\n");
        asm.push_str("    addi sp, sp, 16\n");
        asm.push_str("    ret\n\n");

        asm.push_str(&format!("# Syscall: load_input ({})\n", ckb_abi::syscall::LOAD_INPUT));
        asm.push_str(".global __syscall_load_input\n");
        asm.push_str("__syscall_load_input:\n");
        asm.push_str("    addi sp, sp, -16\n");
        asm.push_str("    sd ra, 8(sp)\n");
        asm.push_str(&format!("    li a7, {}\n", ckb_abi::syscall::LOAD_INPUT));
        asm.push_str("    # a0 = index, a1 = source, a2 = field\n");
        asm.push_str("    ecall\n");
        asm.push_str("    ld ra, 8(sp)\n");
        asm.push_str("    addi sp, sp, 16\n");
        asm.push_str("    ret\n\n");

        asm.push_str(&format!("# Syscall: load_witness ({})\n", ckb_abi::syscall::LOAD_WITNESS));
        asm.push_str(".global __syscall_load_witness\n");
        asm.push_str("__syscall_load_witness:\n");
        asm.push_str("    addi sp, sp, -16\n");
        asm.push_str("    sd ra, 8(sp)\n");
        asm.push_str(&format!("    li a7, {}\n", ckb_abi::syscall::LOAD_WITNESS));
        asm.push_str("    # a0 = index, a1 = source\n");
        asm.push_str("    ecall\n");
        asm.push_str("    ld ra, 8(sp)\n");
        asm.push_str("    addi sp, sp, 16\n");
        asm.push_str("    ret\n\n");

        let load_script_syscall = match target_profile {
            TargetProfile::Ckb => ckb_abi::syscall::LOAD_SCRIPT,
        };
        asm.push_str(&format!("# Syscall: load_script ({})\n", load_script_syscall));
        asm.push_str(".global __syscall_load_script\n");
        asm.push_str("__syscall_load_script:\n");
        asm.push_str("    addi sp, sp, -16\n");
        asm.push_str("    sd ra, 8(sp)\n");
        asm.push_str(&format!("    li a7, {}\n", load_script_syscall));
        asm.push_str("    # a0 = buffer, a1 = size pointer, a2 = offset\n");
        asm.push_str("    ecall\n");
        asm.push_str("    ld ra, 8(sp)\n");
        asm.push_str("    addi sp, sp, 16\n");
        asm.push_str("    ret\n\n");

        asm.push_str(&format!("# Syscall: load_cell_by_field ({})\n", ckb_abi::syscall::LOAD_CELL_BY_FIELD));
        asm.push_str(".global __syscall_load_cell_by_field\n");
        asm.push_str("__syscall_load_cell_by_field:\n");
        asm.push_str("    addi sp, sp, -16\n");
        asm.push_str("    sd ra, 8(sp)\n");
        asm.push_str(&format!("    li a7, {}\n", ckb_abi::syscall::LOAD_CELL_BY_FIELD));
        asm.push_str("    # a0 = buffer, a1 = size pointer, a2 = offset, a3 = index, a4 = source, a5 = field\n");
        asm.push_str("    ecall\n");
        asm.push_str("    ld ra, 8(sp)\n");
        asm.push_str("    addi sp, sp, 16\n");
        asm.push_str("    ret\n\n");

        asm.push_str(&format!("# Syscall: load_cell_data ({})\n", ckb_abi::syscall::LOAD_CELL_DATA));
        asm.push_str(".global __syscall_load_cell_data\n");
        asm.push_str("__syscall_load_cell_data:\n");
        asm.push_str("    addi sp, sp, -16\n");
        asm.push_str("    sd ra, 8(sp)\n");
        asm.push_str(&format!("    li a7, {}\n", ckb_abi::syscall::LOAD_CELL_DATA));
        asm.push_str("    # a0 = buffer, a1 = size pointer, a2 = offset, a3 = index, a4 = source\n");
        asm.push_str("    ecall\n");
        asm.push_str("    ld ra, 8(sp)\n");
        asm.push_str("    addi sp, sp, 16\n");
        asm.push_str("    ret\n\n");

        asm.push_str(&format!("# Syscall: current_cycles ({})\n", ckb_abi::syscall::CURRENT_CYCLES));
        asm.push_str(".global __syscall_current_cycles\n");
        asm.push_str("__syscall_current_cycles:\n");
        asm.push_str("    addi sp, sp, -16\n");
        asm.push_str("    sd ra, 8(sp)\n");
        asm.push_str(&format!("    li a7, {}\n", ckb_abi::syscall::CURRENT_CYCLES));
        asm.push_str("    ecall\n");
        asm.push_str("    ld ra, 8(sp)\n");
        asm.push_str("    addi sp, sp, 16\n");
        asm.push_str("    ret\n\n");

        asm.push_str(&format!("# Syscall: debug_print ({})\n", ckb_abi::syscall::DEBUG));
        asm.push_str(".global __syscall_debug_print\n");
        asm.push_str("__syscall_debug_print:\n");
        asm.push_str("    addi sp, sp, -16\n");
        asm.push_str("    sd ra, 8(sp)\n");
        asm.push_str(&format!("    li a7, {}\n", ckb_abi::syscall::DEBUG));
        asm.push_str("    # a0 = msg pointer, a1 = msg length\n");
        asm.push_str("    ecall\n");
        asm.push_str("    ld ra, 8(sp)\n");
        asm.push_str("    addi sp, sp, 16\n");
        asm.push_str("    ret\n\n");

        asm
    }

    fn generate_math() -> String {
        let mut asm = String::new();

        // math_min
        asm.push_str("# Math: min\n");
        asm.push_str(".global __math_min\n");
        asm.push_str("__math_min:\n");
        asm.push_str("    # a0 = a, a1 = b\n");
        asm.push_str("    blt a0, a1, .Lmin_ret_a\n");
        asm.push_str("    mv a0, a1\n");
        asm.push_str(".Lmin_ret_a:\n");
        asm.push_str("    ret\n\n");

        // math_max
        asm.push_str("# Math: max\n");
        asm.push_str(".global __math_max\n");
        asm.push_str("__math_max:\n");
        asm.push_str("    # a0 = a, a1 = b\n");
        asm.push_str("    bgt a0, a1, .Lmax_ret_a\n");
        asm.push_str("    mv a0, a1\n");
        asm.push_str(".Lmax_ret_a:\n");
        asm.push_str("    ret\n\n");

        asm.push_str("# Math: isqrt (integer square root)\n");
        asm.push_str(".global __math_isqrt\n");
        asm.push_str("__math_isqrt:\n");
        asm.push_str("    addi sp, sp, -32\n");
        asm.push_str("    sd ra, 24(sp)\n");
        asm.push_str("    sd s0, 16(sp)\n");
        asm.push_str("    sd s1, 8(sp)\n");
        asm.push_str("    # a0 = n\n");
        asm.push_str("    beqz a0, .Lisqrt_ret\n");
        asm.push_str("    mv s0, a0          # x = n\n");
        asm.push_str("    srli s1, a0, 1\n");
        asm.push_str("    addi s1, s1, 1     # y = (x + 1) / 2\n");
        asm.push_str(".Lisqrt_loop:\n");
        asm.push_str("    bge s1, s0, .Lisqrt_ret\n");
        asm.push_str("    mv s0, s1          # x = y\n");
        asm.push_str("    div t0, a0, s0\n");
        asm.push_str("    add s1, s0, t0\n");
        asm.push_str("    srli s1, s1, 1     # y = (x + n/x) / 2\n");
        asm.push_str("    j .Lisqrt_loop\n");
        asm.push_str(".Lisqrt_ret:\n");
        asm.push_str("    mv a0, s0\n");
        asm.push_str("    ld ra, 24(sp)\n");
        asm.push_str("    ld s0, 16(sp)\n");
        asm.push_str("    ld s1, 8(sp)\n");
        asm.push_str("    addi sp, sp, 32\n");
        asm.push_str("    ret\n\n");

        // math_abs_diff
        asm.push_str("# Math: abs_diff\n");
        asm.push_str(".global __math_abs_diff\n");
        asm.push_str("__math_abs_diff:\n");
        asm.push_str("    # a0 = a, a1 = b\n");
        asm.push_str("    sub t0, a0, a1\n");
        asm.push_str("    bgez t0, .Labs_diff_ret\n");
        asm.push_str("    neg t0, t0\n");
        asm.push_str(".Labs_diff_ret:\n");
        asm.push_str("    mv a0, t0\n");
        asm.push_str("    ret\n\n");

        asm
    }

    fn generate_env(target_profile: TargetProfile) -> String {
        let mut asm = String::new();

        asm.push_str("# Env: current_timepoint (CKB epoch number, not Unix timestamp)\n");
        asm.push_str(".global __env_current_timepoint\n");
        asm.push_str("__env_current_timepoint:\n");
        asm.push_str("    addi sp, sp, -16\n");
        asm.push_str("    sd ra, 8(sp)\n");
        // All profiles use CKB epoch number.
        asm.push_str("    # Load CKB epoch number from header dep\n");
        asm.push_str(&format!("    li a7, {}  # LOAD_HEADER_BY_FIELD\n", ckb_abi::syscall::LOAD_HEADER_BY_FIELD));
        asm.push_str("    li a0, 0     # header index\n");
        asm.push_str(&format!("    li a1, {}     # field = epoch number\n", ckb_abi::header_field::EPOCH_NUMBER));
        asm.push_str("    ecall\n");
        asm.push_str("    ld ra, 8(sp)\n");
        asm.push_str("    addi sp, sp, 16\n");
        asm.push_str("    ret\n\n");

        Self::push_ckb_header_epoch_helper(
            &mut asm,
            "__ckb_header_epoch_number",
            "ckb_epoch_number",
            ckb_abi::header_field::EPOCH_NUMBER,
            target_profile == TargetProfile::Ckb,
        );
        Self::push_ckb_header_epoch_helper(
            &mut asm,
            "__ckb_header_epoch_start_block_number",
            "ckb_epoch_start_block_number",
            ckb_abi::header_field::EPOCH_START_BLOCK_NUMBER,
            target_profile == TargetProfile::Ckb,
        );
        Self::push_ckb_header_epoch_helper(
            &mut asm,
            "__ckb_header_epoch_length",
            "ckb_epoch_length",
            ckb_abi::header_field::EPOCH_LENGTH,
            target_profile == TargetProfile::Ckb,
        );
        Self::push_ckb_input_since_helper(&mut asm, target_profile == TargetProfile::Ckb);

        // env_remaining_cycles
        asm.push_str("# Env: remaining_cycles\n");
        asm.push_str(".global __env_remaining_cycles\n");
        asm.push_str("__env_remaining_cycles:\n");
        asm.push_str("    addi sp, sp, -16\n");
        asm.push_str("    sd ra, 8(sp)\n");
        asm.push_str(&format!("    li a7, {}  # CURRENT_CYCLES\n", ckb_abi::syscall::CURRENT_CYCLES));
        asm.push_str("    ecall\n");
        asm.push_str("    # a0 = current cycles\n");
        asm.push_str("    li t0, 10000000  # max cycles\n");
        asm.push_str("    sub a0, t0, a0   # remaining\n");
        asm.push_str("    ld ra, 8(sp)\n");
        asm.push_str("    addi sp, sp, 16\n");
        asm.push_str("    ret\n\n");

        asm
    }

    fn push_ckb_header_epoch_helper(asm: &mut String, symbol: &str, field_name: &str, field_id: u64, enabled: bool) {
        asm.push_str(&format!("# Env: {}\n", field_name));
        asm.push_str(&format!(".global {}\n", symbol));
        asm.push_str(&format!("{}:\n", symbol));
        if !enabled {
            asm.push_str("    # rejected outside ckb target-profile policy\n");
            asm.push_str(&format!(
                "    # cellscript runtime error {} {}\n",
                CellScriptRuntimeError::ConsumeInvalidOperand.code(),
                CellScriptRuntimeError::ConsumeInvalidOperand.name()
            ));
            asm.push_str(&format!("    li a0, {}\n", CellScriptRuntimeError::ConsumeInvalidOperand.code()));
            asm.push_str("    ret\n\n");
            return;
        }
        asm.push_str("    addi sp, sp, -32\n");
        asm.push_str("    sd ra, 24(sp)\n");
        asm.push_str("    # Load from CKB header dep\n");
        asm.push_str("    li t0, 8\n");
        asm.push_str("    sd t0, 8(sp)\n");
        asm.push_str("    addi a0, sp, 16\n");
        asm.push_str("    addi a1, sp, 8\n");
        asm.push_str("    li a2, 0     # offset\n");
        asm.push_str("    li a3, 0     # header index\n");
        asm.push_str(&format!("    li a4, {}     # Source::HeaderDep\n", ckb_abi::source::HEADER_DEP));
        asm.push_str(&format!("    li a5, {}     # field = {}\n", field_id, field_name));
        asm.push_str(&format!("    li a7, {}  # LOAD_HEADER_BY_FIELD\n", ckb_abi::syscall::LOAD_HEADER_BY_FIELD));
        asm.push_str("    ecall\n");
        asm.push_str("    ld a0, 16(sp)\n");
        asm.push_str("    ld ra, 24(sp)\n");
        asm.push_str("    addi sp, sp, 32\n");
        asm.push_str("    ret\n\n");
    }

    fn push_ckb_input_since_helper(asm: &mut String, enabled: bool) {
        asm.push_str("# Env: ckb_input_since\n");
        asm.push_str(".global __ckb_input_since\n");
        asm.push_str("__ckb_input_since:\n");
        if !enabled {
            asm.push_str("    # rejected outside ckb target-profile policy\n");
            asm.push_str(&format!(
                "    # cellscript runtime error {} {}\n",
                CellScriptRuntimeError::ConsumeInvalidOperand.code(),
                CellScriptRuntimeError::ConsumeInvalidOperand.name()
            ));
            asm.push_str(&format!("    li a0, {}\n", CellScriptRuntimeError::ConsumeInvalidOperand.code()));
            asm.push_str("    ret\n\n");
            return;
        }
        asm.push_str("    addi sp, sp, -32\n");
        asm.push_str("    sd ra, 24(sp)\n");
        asm.push_str("    # Load CKB input since from current script group\n");
        asm.push_str("    li t0, 8\n");
        asm.push_str("    sd t0, 8(sp)\n");
        asm.push_str("    addi a0, sp, 16\n");
        asm.push_str("    addi a1, sp, 8\n");
        asm.push_str("    li a2, 0     # offset\n");
        asm.push_str("    li a3, 0     # group input index\n");
        asm.push_str(&format!("    li a4, {}  # Source::GroupInput\n", ckb_abi::source::GROUP_INPUT));
        asm.push_str(&format!("    li a5, {}     # field = Since\n", ckb_abi::input_field::SINCE));
        asm.push_str(&format!("    li a7, {}  # LOAD_INPUT_BY_FIELD\n", ckb_abi::syscall::LOAD_INPUT_BY_FIELD));
        asm.push_str("    ecall\n");
        asm.push_str("    ld a0, 16(sp)\n");
        asm.push_str("    ld ra, 24(sp)\n");
        asm.push_str("    addi sp, sp, 32\n");
        asm.push_str("    ret\n\n");
    }
}

#[derive(Debug, Clone)]
pub struct StdFunction {
    pub name: String,
    pub params: Vec<(String, IrType)>,
    pub return_type: Option<IrType>,
}

pub struct SchedulerMetadata;

/// Scheduler-visible CKB runtime access summary.
#[derive(Debug, Clone)]
pub struct SchedulerAccess {
    pub operation: String,
    pub source: String,
    pub index: u32,
    pub binding: String,
}

impl SchedulerMetadata {
    pub fn generate(
        effect_class: &str,
        parallelizable: bool,
        touches_shared: Vec<[u8; 32]>,
        estimated_cycles: u64,
        accesses: Vec<SchedulerAccess>,
    ) -> Vec<u8> {
        Self::generate_molecule(effect_class, parallelizable, touches_shared, estimated_cycles, accesses)
    }

    pub fn generate_molecule(
        effect_class: &str,
        parallelizable: bool,
        touches_shared: Vec<[u8; 32]>,
        estimated_cycles: u64,
        accesses: Vec<SchedulerAccess>,
    ) -> Vec<u8> {
        let effect_class_id = match effect_class {
            "Pure" => 0,
            "ReadOnly" => 1,
            "Mutating" => 2,
            "Creating" => 3,
            "Destroying" => 4,
            _ => 0,
        };

        let accesses = accesses
            .into_iter()
            .map(|access| {
                let mut out = Vec::with_capacity(38);
                out.push(scheduler_operation_id(&access.operation));
                out.push(scheduler_source_id(&access.source));
                out.extend_from_slice(&access.index.to_le_bytes());
                out.extend_from_slice(&ckb_blake2b256(access.binding.as_bytes()));
                out
            })
            .collect::<Vec<_>>();

        scheduler_molecule_encode_table(&[
            0xCE11u16.to_le_bytes().to_vec(),
            vec![1],
            vec![effect_class_id],
            vec![u8::from(parallelizable)],
            (touches_shared.len() as u32).to_le_bytes().to_vec(),
            scheduler_molecule_encode_fixvec_byte32(&touches_shared),
            estimated_cycles.to_le_bytes().to_vec(),
            (accesses.len() as u32).to_le_bytes().to_vec(),
            scheduler_molecule_encode_fixvec_access(&accesses),
        ])
    }
}

fn scheduler_operation_id(operation: &str) -> u8 {
    match operation {
        "consume" => 1,
        "transfer" => 2,
        "destroy" => 3,
        "claim" => 4,
        "settle" => 5,
        "read_ref" => 6,
        "create" => 7,
        "mutate-input" => 8,
        "mutate-output" => 9,
        _ => 0,
    }
}

fn scheduler_source_id(source: &str) -> u8 {
    match source {
        "Input" => 1,
        "CellDep" => 2,
        "Output" => 3,
        _ => 0,
    }
}

fn scheduler_molecule_pack_number(value: usize) -> [u8; 4] {
    (value as u32).to_le_bytes()
}

fn scheduler_molecule_encode_table(fields: &[Vec<u8>]) -> Vec<u8> {
    let header_size = 4 * (fields.len() + 1);
    let total_size = header_size + fields.iter().map(Vec::len).sum::<usize>();
    let mut out = Vec::with_capacity(total_size);
    out.extend_from_slice(&scheduler_molecule_pack_number(total_size));

    let mut offset = header_size;
    for field in fields {
        out.extend_from_slice(&scheduler_molecule_pack_number(offset));
        offset += field.len();
    }
    for field in fields {
        out.extend_from_slice(field);
    }
    out
}

fn scheduler_molecule_encode_fixvec_byte32(values: &[[u8; 32]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + values.len() * 32);
    out.extend_from_slice(&scheduler_molecule_pack_number(values.len()));
    for value in values {
        out.extend_from_slice(value);
    }
    out
}

fn scheduler_molecule_encode_fixvec_access(accesses: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + accesses.iter().map(Vec::len).sum::<usize>());
    out.extend_from_slice(&scheduler_molecule_pack_number(accesses.len()));
    for access in accesses {
        out.extend_from_slice(access);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_std_functions() {
        let funcs = StdLib::functions();
        assert!(!funcs.is_empty());
        assert!(StdLib::is_std_function("syscall_load_cell"));
        assert!(StdLib::is_std_function("syscall_load_script"));
        assert!(StdLib::is_std_function("syscall_load_cell_by_field"));
        assert!(StdLib::is_std_function("syscall_load_cell_data"));
        assert!(StdLib::is_std_function("math_isqrt"));
    }

    #[test]
    fn test_get_function() {
        let func = StdLib::get_function("math_min");
        assert!(func.is_some());
        let func = func.unwrap();
        assert_eq!(func.params.len(), 2);
    }

    #[test]
    fn test_generate_assembly() {
        let asm = StdLib::generate_assembly();
        assert!(asm.contains("__syscall_load_cell"));
        assert!(asm.contains("__syscall_load_script:\n"));
        assert!(asm.contains("__syscall_load_cell_by_field:\n"));
        assert!(asm.contains("__syscall_load_cell_data:\n"));
        // Default is now CKB profile which uses 2052 for load_script
        assert!(asm.contains("li a7, 2052"));
        assert!(asm.contains("li a7, 2081"));
        assert!(asm.contains("li a7, 2092"));
        assert!(!asm.contains("__hash"));
        assert!(!asm.contains("3001"));
        assert!(!asm.contains("li a7, 2100"));
        assert!(asm.contains("__math_isqrt"));
    }

    #[test]
    fn test_generate_ckb_assembly_uses_ckb_load_script_syscall() {
        let asm = StdLib::generate_assembly_for_target_profile(TargetProfile::Ckb);
        assert!(asm.contains("# Syscall: load_script (2052)"));
        assert!(asm.contains("li a7, 2052"));
        assert!(!asm.contains("li a7, 2075"));
        assert!(asm.contains("current_timepoint"));
        assert!(asm.contains("__ckb_input_since"));
        assert!(asm.contains("li a7, 2083  # LOAD_INPUT_BY_FIELD"));
        assert!(asm.contains("Source::GroupInput"));
    }

    #[test]
    fn test_scheduler_metadata_generate_molecule_uses_table_layout() {
        let bytes = SchedulerMetadata::generate(
            "Creating",
            false,
            vec![[0x42; 32]],
            64,
            vec![SchedulerAccess {
                operation: "create".to_string(),
                source: "Output".to_string(),
                index: 0,
                binding: "create:Output#0".to_string(),
            }],
        );

        assert!(!bytes.starts_with(&[0x11, 0xCE, 1]));
        assert_eq!(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize, bytes.len());
        assert_eq!(u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]), 40);
        assert_eq!(&bytes[40..42], &[0x11, 0xCE]);
    }
}
