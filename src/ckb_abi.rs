//! CKB ABI constants used by CellScript's inline verifier backend.
//!
//! Keep this module as the single CellScript-owned mirror of the CKB syscall,
//! source, field, and since values exposed by `ckb-std::ckb_constants`.

pub mod syscall {
    pub const EXIT: u64 = 93;
    pub const VM_VERSION: u64 = 2041;
    pub const CURRENT_CYCLES: u64 = 2042;
    pub const EXEC: u64 = 2043;
    pub const LOAD_TRANSACTION: u64 = 2051;
    pub const LOAD_SCRIPT: u64 = 2052;
    pub const LOAD_TX_HASH: u64 = 2061;
    pub const LOAD_SCRIPT_HASH: u64 = 2062;
    pub const LOAD_CELL: u64 = 2071;
    pub const LOAD_HEADER: u64 = 2072;
    pub const LOAD_INPUT: u64 = 2073;
    pub const LOAD_WITNESS: u64 = 2074;
    pub const LOAD_CELL_BY_FIELD: u64 = 2081;
    pub const LOAD_HEADER_BY_FIELD: u64 = 2082;
    pub const LOAD_INPUT_BY_FIELD: u64 = 2083;
    pub const LOAD_CELL_DATA_AS_CODE: u64 = 2091;
    pub const LOAD_CELL_DATA: u64 = 2092;
    pub const LOAD_BLOCK_EXTENSION: u64 = 2104;
    pub const DEBUG: u64 = 2177;
    pub const SPAWN: u64 = 2601;
    pub const WAIT: u64 = 2602;
    pub const PROCESS_ID: u64 = 2603;
    pub const PIPE: u64 = 2604;
    pub const WRITE: u64 = 2605;
    pub const READ: u64 = 2606;
    pub const INHERITED_FDS: u64 = 2607;
    pub const CLOSE: u64 = 2608;
}

pub mod source {
    pub const INPUT: u64 = 1;
    pub const OUTPUT: u64 = 2;
    pub const CELL_DEP: u64 = 3;
    pub const HEADER_DEP: u64 = 4;
    pub const GROUP_FLAG: u64 = 0x0100_0000_0000_0000;
    pub const GROUP_INPUT: u64 = GROUP_FLAG | INPUT;
    pub const GROUP_OUTPUT: u64 = GROUP_FLAG | OUTPUT;
}

pub mod cell_field {
    pub const CAPACITY: u64 = 0;
    pub const DATA_HASH: u64 = 1;
    pub const LOCK: u64 = 2;
    pub const LOCK_HASH: u64 = 3;
    pub const TYPE: u64 = 4;
    pub const TYPE_HASH: u64 = 5;
    pub const OCCUPIED_CAPACITY: u64 = 6;
}

pub mod header_field {
    pub const EPOCH_NUMBER: u64 = 0;
    pub const EPOCH_START_BLOCK_NUMBER: u64 = 1;
    pub const EPOCH_LENGTH: u64 = 2;
}

pub mod input_field {
    pub const OUT_POINT: u64 = 0;
    pub const SINCE: u64 = 1;
}

pub mod place {
    pub const CELL: u64 = 0;
    pub const WITNESS: u64 = 1;
}

pub mod syscall_error {
    pub const SUCCESS: u64 = 0;
    pub const INDEX_OUT_OF_BOUND: u64 = 1;
    pub const ITEM_MISSING: u64 = 2;
    pub const LENGTH_NOT_ENOUGH: u64 = 3;
}

pub mod since {
    pub const RELATIVE_FLAG: u64 = 0x8000_0000_0000_0000;
    pub const METRIC_TYPE_FLAG_MASK: u64 = 0x6000_0000_0000_0000;
    pub const BLOCK_NUMBER_FLAG: u64 = 0x0000_0000_0000_0000;
    pub const EPOCH_NUMBER_WITH_FRACTION_FLAG: u64 = 0x2000_0000_0000_0000;
    pub const TIMESTAMP_FLAG: u64 = 0x4000_0000_0000_0000;
    pub const REMAIN_FLAGS_BITS: u64 = 0x1f00_0000_0000_0000;
    pub const VALUE_MASK: u64 = 0x00ff_ffff_ffff_ffff;
    /// Exclusive upper bound for a timestamp payload whose consensus
    /// seconds-to-milliseconds conversion remains inside `u64`.
    pub const TIMESTAMP_VALUE_BOUND: u64 = u64::MAX / 1_000 + 1;
    pub const EPOCH_NUMBER_BOUND: u64 = 1 << 24;
    pub const EPOCH_FRACTION_BOUND: u64 = 1 << 16;
    pub const EPOCH_NUMBER_MASK: u64 = EPOCH_NUMBER_BOUND - 1;
    pub const EPOCH_FRACTION_MASK: u64 = EPOCH_FRACTION_BOUND - 1;
}

/// Fixed Molecule layout from CKB's `blockchain.mol` `Header` struct.
pub mod header {
    pub const SERIALIZED_SIZE: usize = 208;
    pub const TIMESTAMP_OFFSET: usize = 8;
    pub const NUMBER_OFFSET: usize = 16;
    pub const SCALAR_WIDTH: usize = 8;
}

pub mod source_view {
    pub const INPUT: u64 = 1;
    pub const OUTPUT: u64 = 2;
    pub const CELL_DEP: u64 = 3;
    pub const HEADER_DEP: u64 = 4;
    pub const GROUP_INPUT: u64 = 5;
    pub const GROUP_OUTPUT: u64 = 6;
    pub const SHIFT: u64 = 4_294_967_296;
}

pub mod type_id {
    /// Built-in CKB TYPE_ID Script code hash.
    pub const CODE_HASH: [u8; 32] =
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, b'T', b'Y', b'P', b'E', b'_', b'I', b'D'];

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Lifecycle {
        Mint,
        Continue,
        Burn,
    }

    pub fn lifecycle_for_group_counts(group_input_count: usize, group_output_count: usize) -> Option<Lifecycle> {
        match (group_input_count, group_output_count) {
            (0, 1) => Some(Lifecycle::Mint),
            (1, 1) => Some(Lifecycle::Continue),
            (1, 0) => Some(Lifecycle::Burn),
            _ => None,
        }
    }

    pub fn args_from_first_input_and_output_index(first_input: &[u8], output_index: u64) -> [u8; 32] {
        let output_index = output_index.to_le_bytes();
        crate::ckb_blake2b256_parts(&[first_input, &output_index])
    }
}

pub fn encode_source_view(view: u64, index: u64) -> Option<u64> {
    if index >= source_view::SHIFT {
        return None;
    }
    match view {
        source_view::INPUT
        | source_view::OUTPUT
        | source_view::CELL_DEP
        | source_view::HEADER_DEP
        | source_view::GROUP_INPUT
        | source_view::GROUP_OUTPUT => view.checked_mul(source_view::SHIFT)?.checked_add(index),
        _ => None,
    }
}

pub fn decode_source_view(value: u64) -> Option<(u64, u64)> {
    // `index == 0` is valid. In particular, exact multiples of SHIFT encode
    // the first item in a source view; the quotient is the closed view tag.
    let view = value / source_view::SHIFT;
    let index = value % source_view::SHIFT;
    let source = match view {
        source_view::INPUT => source::INPUT,
        source_view::OUTPUT => source::OUTPUT,
        source_view::CELL_DEP => source::CELL_DEP,
        source_view::HEADER_DEP => source::HEADER_DEP,
        source_view::GROUP_INPUT => source::GROUP_INPUT,
        source_view::GROUP_OUTPUT => source::GROUP_OUTPUT,
        _ => return None,
    };
    Some((source, index))
}
