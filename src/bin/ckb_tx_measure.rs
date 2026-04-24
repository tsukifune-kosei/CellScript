use std::io::{self, Read};

use ckb_jsonrpc_types::{JsonBytes, Transaction as JsonTransaction};
use ckb_types::{core::Capacity, packed, prelude::Entity};
use serde::Serialize;

#[derive(Serialize)]
struct TxMeasure {
    consensus_serialized_tx_size_bytes: usize,
    occupied_capacity_shannons: u64,
    output_occupied_capacity_shannons: Vec<u64>,
    output_capacity_shannons: Vec<u64>,
    capacity_is_sufficient: bool,
    under_capacity_output_indexes: Vec<usize>,
}

fn occupied_capacity_for_output(
    output: &ckb_jsonrpc_types::CellOutput,
    data_hex: &JsonBytes,
) -> Result<u64, Box<dyn std::error::Error>> {
    let output: packed::CellOutput = output.clone().into();
    let data_capacity = Capacity::bytes(data_hex.len())?;
    Ok(output.occupied_capacity(data_capacity)?.as_u64())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    let json_tx: JsonTransaction = serde_json::from_str(&input)?;
    if json_tx.outputs.len() != json_tx.outputs_data.len() {
        return Err(format!(
            "transaction outputs/outputs_data length mismatch: {} outputs, {} outputs_data entries",
            json_tx.outputs.len(),
            json_tx.outputs_data.len()
        )
        .into());
    }
    let packed_tx: packed::Transaction = json_tx.clone().into();

    let consensus_serialized_tx_size_bytes = packed_tx.as_bytes().len();

    let mut output_occupied_capacity_shannons = Vec::with_capacity(json_tx.outputs.len());
    let mut output_capacity_shannons = Vec::with_capacity(json_tx.outputs.len());
    let mut under_capacity_output_indexes = Vec::new();
    let mut occupied_capacity = 0u64;

    for (index, (output, data)) in json_tx.outputs.iter().zip(json_tx.outputs_data.iter()).enumerate() {
        let required = occupied_capacity_for_output(output, data)?;
        let packed_output: packed::CellOutput = output.clone().into();
        let actual_capacity = Capacity::from(packed_output.capacity()).as_u64();
        output_occupied_capacity_shannons.push(required);
        output_capacity_shannons.push(actual_capacity);
        if actual_capacity < required {
            under_capacity_output_indexes.push(index);
        }
        occupied_capacity = occupied_capacity.checked_add(required).ok_or("occupied capacity overflow")?;
    }

    let capacity_is_sufficient = under_capacity_output_indexes.is_empty();

    serde_json::to_writer(
        io::stdout(),
        &TxMeasure {
            consensus_serialized_tx_size_bytes,
            occupied_capacity_shannons: occupied_capacity,
            output_occupied_capacity_shannons,
            output_capacity_shannons,
            capacity_is_sufficient,
            under_capacity_output_indexes,
        },
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn output_with_lock_args(args_hex: &str) -> ckb_jsonrpc_types::CellOutput {
        serde_json::from_value(json!({
            "capacity": "0x0",
            "lock": {
                "code_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "hash_type": "type",
                "args": args_hex
            },
            "type": null
        }))
        .expect("valid json cell output")
    }

    fn json_bytes(hex: &str) -> JsonBytes {
        serde_json::from_value(json!(hex)).expect("valid json bytes")
    }

    #[test]
    fn occupied_capacity_uses_ckb_capacity_units() {
        let output = output_with_lock_args("0x");
        assert_eq!(occupied_capacity_for_output(&output, &json_bytes("0x")).unwrap(), 41 * 100_000_000);
        assert_eq!(occupied_capacity_for_output(&output, &json_bytes("0x0102")).unwrap(), 43 * 100_000_000);
    }

    #[test]
    fn occupied_capacity_counts_lock_args() {
        let output = output_with_lock_args("0x0000000000000000000000000000000000000000");
        assert_eq!(occupied_capacity_for_output(&output, &json_bytes("0x")).unwrap(), 61 * 100_000_000);
    }
}
