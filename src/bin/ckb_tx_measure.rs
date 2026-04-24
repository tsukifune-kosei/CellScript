use std::io::{self, Read};

use ckb_jsonrpc_types::{JsonBytes, Transaction as JsonTransaction};
use ckb_types::{packed, prelude::Entity};
use serde::Serialize;

#[derive(Serialize)]
struct TxMeasure {
    consensus_serialized_tx_size_bytes: usize,
    occupied_capacity_shannons: u64,
    output_occupied_capacity_shannons: Vec<u64>,
}

fn occupied_capacity_for_output(
    output: &ckb_jsonrpc_types::CellOutput,
    data_hex: &JsonBytes,
) -> Result<u64, Box<dyn std::error::Error>> {
    let mut size = 8u64;
    size += 32 + 1 + output.lock.args.len() as u64;
    if let Some(type_script) = &output.type_ {
        size += 32 + 1 + type_script.args.len() as u64;
    }
    size += data_hex.len() as u64;
    Ok(size)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    let json_tx: JsonTransaction = serde_json::from_str(&input)?;
    let packed_tx: packed::Transaction = json_tx.clone().into();

    let consensus_serialized_tx_size_bytes = packed_tx.as_bytes().len();

    let mut output_occupied_capacity_shannons = Vec::with_capacity(json_tx.outputs.len());
    let mut occupied_capacity = 0u64;

    for (output, data) in json_tx.outputs.iter().zip(json_tx.outputs_data.iter()) {
        let required = occupied_capacity_for_output(output, data)?;
        output_occupied_capacity_shannons.push(required);
        occupied_capacity = occupied_capacity.checked_add(required).ok_or("occupied capacity overflow")?;
    }

    serde_json::to_writer(
        io::stdout(),
        &TxMeasure {
            consensus_serialized_tx_size_bytes,
            occupied_capacity_shannons: occupied_capacity,
            output_occupied_capacity_shannons,
        },
    )?;
    Ok(())
}
